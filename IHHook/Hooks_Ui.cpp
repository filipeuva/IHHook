// Hooks_Ui.cpp — Add-our-own Window + inject UiModelText (F7)  |  Dump (F8)  |  Inspect (F9/F10)
//
// Hotkeys:
//   F7  -> Create our own Window (via last seen WindowFunction*), add it under a known parent window,
//          create a UiModelText using a harvested creation context, and connect it to our window’s graph.
//   F8  -> Dump injection status (window/layout/parent/port/node/visible/text)
//   F9  -> Dump common[] ports for known layouts (debug)
//   F10 -> Resolve anchors for layouts (legacy layout route; kept for convenience)
//
// Notes:
//  • We harvest a *valid* ModelNodeText creation context at runtime by hooking NewUiModelText.
//  • For windows, NodeConnectShim follows the same shape as in Window::AddChild:
//      parentComp = *(window + 0x28), port = parentComp ? parentComp + 0x60 : nullptr.
//  • We learn candidate parent windows by hooking Window::AddChild and caching the parent pointer.
//  • We capture a usable WindowFunction* (CreateWindow’s RCX) to instantiate our own window later.
//  • Text auto-refreshes when g_camoIndex changes.
//
// Requires in mgsvtpp_func_typedefs.h:
//   void* __fastcall GetModelWrapper(void* layout, void** outModel, uint32_t wantRoot);
//   void*  __fastcall GetModelNodeFromIndex(const void* model, int index);
//   void*  __fastcall NewUiModelText(uint32_t, void*, void*, void*);
//   void   __fastcall SetTextForModelNodeText(void* uix, void* nodeText, void* textUnit, const char* text, bool isLoc);
//   void   __fastcall SetModelNodePriority(void* uix, void* node, int prio);
//   void   __fastcall SetModelNodeTextFontSize(void* uix, void* node, float size, float tracking);
//   void   __fastcall SetModelNodeTextColorRGB(void* uix, void* node, float r, float g, float b);
//   bool   __fastcall IsNodeVisible(void* anyMgr, void* node);
//   void*  __fastcall GetModelNodeCommon(void* selfModel);
//   void*  __fastcall GetModelNodeCommonInternal(void* selfModel, uint32_t);
//   bool   __fastcall IsHaveModelNodeCommon(void* uixUtil, const void* model, uint64_t sid);
//   void   __fastcall NodeConnectShim(void* node, void* parentComp, void* portNode);
//   void** GetGlobalUixUtility();
//
//   // Window route
//   void  __fastcall UpdateWindowGraph(void* pWindow);
//   void  __fastcall AddChildWindow(void* parentWindow, void* childWindow);
//   void* __fastcall CreateNewWindow(void* windowFunction /*RCX*/, const void* nameStr /*RDX*/, uint32_t flagsA /*R8D*/, uint32_t flagsB /*R9D*/);
//   void* __fastcall GetWindowManager();
//
//   // Engine tick
//   void  __fastcall UpdatePhaseUi(void* phase);
//
// Hook macros expected:
//   CREATE_HOOK(FuncName)
//   ENABLEHOOK(FuncName)

#include "Hooks_Ui.h"
#include "IHHook.h"
#include "hooks/mgsvtpp_func_typedefs.h"
#include "MinHook.h"
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"

#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <climits>
#include <string>

namespace IHHook
{
    namespace Hooks_Ui
    {
        // -----------------------------------------------------------------------------
        // Globals / state
        // -----------------------------------------------------------------------------
        static std::mutex g_mx;

        static std::unordered_set<void*> g_knownLayouts;
        static std::unordered_map<void*, void*> g_layoutByModel;
        static std::unordered_map<void*, uint32_t> g_modelNodeCount;
        static std::unordered_set<void*> g_enumeratedModels;

        static std::unordered_map<void*, std::vector<void*>> g_nodesByLayout;
        static std::unordered_multimap<void*, void*> g_layoutsByNode;
        static std::unordered_map<void*, std::pair<void*, const void*>> g_anchorByNode;
        static std::unordered_map<void*, std::pair<void*, const void*>> g_anchorForLayout;
        static std::unordered_map<void*, void*> g_injectedNodeByLayout; // legacy layout path (kept)
        static std::unordered_set<void*> g_ourNodes;

        static std::unordered_map<void*, std::string> g_textByNode;
        static std::unordered_map<void*, uint32_t> g_sidByNode;
        static std::unordered_map<void*, bool> g_visByNode;
        static std::unordered_map<void*, void*> g_primaryModelByLayout;


        // -----------------------------------------------------------------------------
        // TARGET LAYOUT SIGNATURES (fill with the one(s) you want)
        // -----------------------------------------------------------------------------
        // How to get: run with this patch, open the HUD/layout you want, press F8 and copy the
        // printed "sig64=..." for the layout you care about, then put it here.
        static std::unordered_set<uint64_t> g_targetLayoutSigs = {
            // example placeholders — replace with your real ones once discovered via F8
            // 0xB7E8F8C02F76A8A1ull,
            // 0xA4205B3D3C9730D9ull,
            0x6E6A53858C7D348A, // Main Menu
            0xF9325CE34EBD7F47, // HUD
            0x74E5E1FF080986D1, // iDroid
        };

        // --- signatures & anchors ---
        static std::unordered_map<void*, uint64_t> g_sigByModel; // model -> modelSig (per visible state)
        static std::unordered_map<void*, uint64_t> g_currentSigByLayout; // layout -> last modelSig we saw for it
        static std::unordered_map<uint64_t, std::pair<void*, const void*>> g_anchorBySig;
        // sig64 -> (parentComp, portNode)

        static std::unordered_map<void*, std::unordered_set<void*>> g_modelsOfLayout; // layout -> models

        static std::unordered_map<void*, uint64_t> g_layoutAggSig; // layout -> aggregate sig

        // WindowFunction classes we’ve seen during CreateNewWindow
        static std::unordered_set<void*> g_seenWindowFunctions;

        // Factory registry (if you want to pivot off RegisterWindowFactory too)
        static std::unordered_map<int, void*> g_factoryById;

        // Layout -> computed signature (so we don’t recompute constantly)
        static std::unordered_map<void*, uint64_t> g_sigByLayout;

        // Layouts that matched our target signature
        static std::unordered_set<void*> g_targetLayouts;

        // Class -> (layoutId -> sig) cache to accelerate F7 scans
        static std::unordered_map<void*, std::unordered_map<uint64_t, uint64_t>> g_sigCacheByClass;

        static std::atomic<int> g_camoIndex{-1};

        // --- NEW: creation-context & window plumbing ---
        static std::atomic<void*> g_lastTextCreationCtx{nullptr};
        static std::atomic<uint32_t> g_lastTextSceneStr{0};

        static std::unordered_set<void*> g_knownParentWindows; // from AddChildWindow(parent, child)
        static std::atomic<void*> g_lastWindowFunctionClass{nullptr}; // captured from CreateNewWindow RCX
        static std::atomic<void*> g_myWindow{nullptr};
        static std::atomic<void*> g_myTextNode{nullptr};

        // -----------------------------------------------------------------------------
        // Utilities
        // -----------------------------------------------------------------------------
        template <class F>
        static bool Seh(const char* tag, void* ctx, F&& fn)
        {
#if defined(_MSC_VER)
            __try
            {
                fn();
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                spdlog::warn("[SEH] {} ctx={}", tag, ctx);
                return false;
            }
#else
            try { fn(); return true; } catch (...) { spdlog::warn("[SEH] {} ctx={}", tag, ctx); return false; }
#endif
        }

        static inline void RememberText(void* node, const char* t)
        {
            if (!node || !t) return;
            std::lock_guard<std::mutex> _l(g_mx);
            g_textByNode[node] = t;
        }

        static inline void RememberSid(void* node, uint64_t sid)
        {
            if (!node) return;
            std::lock_guard<std::mutex> _l(g_mx);
            g_sidByNode[node] = sid;
        }

        static inline void RememberVis(void* node, bool v)
        {
            if (!node) return;
            std::lock_guard<std::mutex> _l(g_mx);
            g_visByNode[node] = v;
        }

        static inline void BindNodeUnderLayout(void* node, void* layout)
        {
            if (!node || !layout) return;
            auto& vec = g_nodesByLayout[layout];
            if (std::find(vec.begin(), vec.end(), node) == vec.end())
            {
                vec.push_back(node);
                g_layoutsByNode.emplace(node, layout);
            }
        }

        static void UpdateTextForNode(void* uix, void* node)
        {
            if (!uix || !node) return;
            int v = g_camoIndex.load();
            char buf[64];
            if (v >= 0) _snprintf_s(buf, _TRUNCATE, "Camo: %d", v);
            else _snprintf_s(buf, _TRUNCATE, "Camo: ?");
            SetTextForModelNodeText(uix, node, nullptr, buf, false);
            RememberText(node, buf);
        }

        static void MaybeRefreshInjectedText()
        {
            static int prev = INT_MIN;
            int v = g_camoIndex.load();
            if (v == prev) return;
            prev = v;

            void** ppUix = GetGlobalUixUtility();
            void* uix = ppUix ? *ppUix : nullptr;
            if (!uix) return;

            // Refresh layout path nodes
            std::vector<void*> nodes;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                nodes.reserve(g_injectedNodeByLayout.size());
                for (auto& kv : g_injectedNodeByLayout) nodes.push_back(kv.second);
            }
            for (void* n : nodes) UpdateTextForNode(uix, n);

            // Refresh window path node
            if (void* n = g_myTextNode.load())
            {
                UpdateTextForNode(uix, n);
            }
        }

        static inline uint64_t Fnv1a64(const void* data, size_t len)
        {
            const uint8_t* p = static_cast<const uint8_t*>(data);
            uint64_t h = 1469598103934665603ull; // FNV offset basis
            for (size_t i = 0; i < len; ++i)
            {
                h ^= p[i];
                h *= 1099511628211ull;
            }
            return h;
        }

        static uint64_t RecomputeLayoutAggSig(void* layout)
        {
            std::vector<uint64_t> sigs;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                auto& S = g_modelsOfLayout[layout];
                sigs.reserve(S.size());
                for (auto m : S)
                {
                    auto it = g_sigByModel.find(m);
                    if (it != g_sigByModel.end() && it->second) sigs.push_back(it->second);
                }
            }
            if (sigs.empty()) return 0;
            std::sort(sigs.begin(), sigs.end());
            sigs.erase(std::unique(sigs.begin(), sigs.end()), sigs.end());
            const uint64_t agg = Fnv1a64(sigs.data(), sigs.size() * sizeof(uint64_t));
            {
                std::lock_guard<std::mutex> _l(g_mx);
                g_layoutAggSig[layout] = agg;
                if (g_targetLayoutSigs.count(agg)) g_targetLayouts.insert(layout);
            }
            return agg;
        }

        static inline uint64_t RebasedPtr(const void* p)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.AllocationBase)
            {
                return (uint64_t)((uintptr_t)p - (uintptr_t)mbi.AllocationBase);
            }
            // Fallback if VirtualQuery fails (should be rare)
            return (uint64_t)(uintptr_t)p;
        }

        // Read up to N "common" node SIDs (UiModelNodeCommon->name SID at +0x6C) and build a stable hash.
        // We sort & sample to get a small, order-invariant signature that survives minor reorderings.
        static uint64_t ComputeLayoutSigFromModel(void* model, uint32_t sampleMax = 128)
        {
            if (!model) return 0;

            std::vector<void*> nodes;
            nodes.reserve(sampleMax);
            for (int i = 0; i < 4096 && (uint32_t)nodes.size() < sampleMax; ++i)
            {
                void* n = GetModelNodeFromIndex(model, i);
                if (!n) break;
                nodes.push_back(n);
            }
            if (nodes.empty()) return 0;

            std::vector<uint64_t> parts;
            parts.reserve(nodes.size());

            for (void* n : nodes)
            {
                void** vtbl = *reinterpret_cast<void***>(n);
                parts.push_back(RebasedPtr(vtbl)); // ASLR-invariant
            }
            if (parts.empty()) return 0;

            std::sort(parts.begin(), parts.end());
            if (parts.size() > sampleMax) parts.resize(sampleMax);
            return Fnv1a64(parts.data(), parts.size() * sizeof(uint64_t));
        }

        // Get (or compute) a layout signature using its primary model.
        static uint64_t GetOrComputeLayoutSig(void* layout)
        {
            if (!layout) return 0;

            {
                std::lock_guard<std::mutex> _l(g_mx);
                auto it = g_sigByLayout.find(layout);
                if (it != g_sigByLayout.end() && it->second) return it->second;
            }

            // Optional fallback (no arg tampering):
            void* model = nullptr;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                auto it = g_primaryModelByLayout.find(layout);
                if (it != g_primaryModelByLayout.end()) model = it->second;
            }

            const uint64_t sig = ComputeLayoutSigFromModel(model);
            if (sig)
            {
                std::lock_guard<std::mutex> _l(g_mx);
                g_sigByLayout[layout] = sig;
                if (g_targetLayoutSigs.count(sig)) g_targetLayouts.insert(layout);
            }
            return sig;
        }

        // -----------------------------------------------------------------------------
        // Layout model discovery (legacy helpers retained for debugging/comparison)
        // -----------------------------------------------------------------------------
        static thread_local bool tls_inEnum = false;

        static size_t EnumerateModelNodes(void* model, void* layout, uint32_t maxNodes = 4096)
        {
            if (!model || !layout) return 0;
            if (tls_inEnum) return 0;
            if (g_enumeratedModels.count(model)) return 0;

            size_t added = 0;
            tls_inEnum = true;
            bool ok = Seh("EnumerateModelNodes", model, [&]
            {
                for (uint32_t i = 0; i < maxNodes; ++i)
                {
                    void* node = nullptr;
                    bool got = Seh("GetModelNodeFromIndex", (void*)model, [&]
                    {
                        node = GetModelNodeFromIndex(model, (int)i);
                    });
                    if (!got || !node) break;
                    BindNodeUnderLayout(node, layout);
                    ++added;
                }
            });
            tls_inEnum = false;

            if (ok)
            {
                if (added) spdlog::info("[ENUM] model={} -> {} nodes (layout={})", model, added, layout);
                std::lock_guard<std::mutex> _l(g_mx);
                g_enumeratedModels.insert(model);
                g_modelNodeCount[model] = (uint32_t)added;
            }
            else
            {
                spdlog::warn("[ENUM] model={} aborted (SEH)", model);
            }
            return added;
        }

        static void* PickAnchorModelForLayout(void* layout)
        {
            if (!layout) return nullptr;

            void* model = nullptr;
            Seh("GetModelWrapper.probe", layout, [&]
            {
                model = GetModelWrapper(layout, nullptr, 0);
                if (model && !GetModelNodeFromIndex(model, 0)) model = nullptr;
            });
            if (model) return model;

            void* bestModel = nullptr;
            uint32_t bestCount = 0;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                for (auto& kv : g_layoutByModel)
                {
                    if (kv.second != layout) continue;
                    uint32_t cnt = 0;
                    auto it = g_modelNodeCount.find(kv.first);
                    if (it != g_modelNodeCount.end()) cnt = it->second;
                    if (cnt > bestCount)
                    {
                        bestCount = cnt;
                        bestModel = kv.first;
                    }
                }
            }
            return bestModel;
        }

        // Dump model common ports (debug)
        static const void* TryGetAnyCommonPort(void* model)
        {
            const void* port = nullptr;
            Seh("GetModelNodeCommon", model, [&] { port = GetModelNodeCommon(model); });
            if (port) return port;

            Seh("ScanCommonPorts", model, [&]
            {
                auto base = *reinterpret_cast<void***>(reinterpret_cast<uint8_t*>(model) + 0x98);
                auto count = *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(model) + 0x90);
                if (base && count)
                {
                    for (uint32_t i = 0; i < count; ++i)
                    {
                        if (base[i])
                        {
                            port = base[i];
                            break;
                        }
                    }
                }
            });
            return port;
        }

        static void DumpCommonPortsForLayout(void* layout)
        {
            void* model = PickAnchorModelForLayout(layout);
            if (!model)
            {
                spdlog::info("[PORT] layout={} no model", layout);
                return;
            }

            Seh("DumpCommonPorts", model, [&]
            {
                auto base = *reinterpret_cast<void***>(reinterpret_cast<uint8_t*>(model) + 0x98);
                auto count = *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(model) + 0x90);
                spdlog::info("[PORT] layout={} model={} commonCount={}", layout, model, count);
                if (!base || !count) return;

                for (uint32_t i = 0; i < count; ++i)
                {
                    void* node = base[i];
                    if (!node) continue;
                    uint32_t sid = 0;
                    Seh("ReadCommonSid", node, [&]
                    {
                        sid = *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(node) + 0x6C);
                    });
                    spdlog::info("[PORT]   [{}] node={} sid=#{:08X}", i, node, sid);
                }
            });
        }

        static bool TryResolveAnchorForLayout(void* layout, std::pair<void*, const void*>& out)
        {
            if (!layout) return false;
            void* model = PickAnchorModelForLayout(layout);
            if (!model) return false;

            // Heuristic: find which layout field’s +0x60 points to ANY valid common[] node.
            const void* anyCommon = TryGetAnyCommonPort(model); // returns a node*, VALUE of the field
            if (!anyCommon) return false;

            void* parentComp = nullptr;
            for (size_t off = 0x20; off <= 0x80; off += 8) {
                void* cand = nullptr; Seh("read layout field", layout, [&]{ cand = *(void**)((uint8_t*)layout + off); });
                if (!cand) continue;
                void* candVal = nullptr; Seh("read cand +0x60", cand, [&]{ candVal = *(void**)((uint8_t*)cand + 0x60); });
                if (candVal == anyCommon) { parentComp = cand; break; }
            }
            if (!parentComp) return false;

            const void* portPtr = (const void*)((uint8_t*)parentComp + 0x60);
            out = { parentComp, portPtr };
            spdlog::info("[ROOT] layout={} anchor via common[]: parentComp={} portPtr={}", layout, parentComp, portPtr);
            return true;
        }

        static size_t ResolveAnchors_AllLayouts()
        {
            std::vector<void*> layouts;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                for (auto& L : g_knownLayouts)
                    if (!g_anchorForLayout.count(L)) layouts.push_back(L);
            }
            size_t made = 0;
            for (void* L : layouts)
            {
                std::pair<void*, const void*> a{};
                if (TryResolveAnchorForLayout(L, a))
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    g_anchorForLayout[L] = a;
                    ++made;
                }
            }
            return made;
        }

        static bool FindMatchingLayoutInClass(void* cls, uint64_t& outId, uint64_t& outSig)
        {
            if (!cls) return false;
            std::vector<uint64_t> ids;
            {
                // snapshot known ids for this class
                std::lock_guard<std::mutex> _l(g_mx);
                auto it = g_sigCacheByClass.find(cls);
                if (it != g_sigCacheByClass.end())
                    for (auto& kv : it->second) ids.push_back(kv.first);
            }
            // First pass: use cached sigs; second pass: compute sigs for ids missing a value
            for (auto id : ids)
            {
                uint64_t sig = 0;
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    sig = g_sigCacheByClass[cls][id];
                }
                if (!sig)
                {
                    if (void* L = GetWindowLayout(cls, id))
                    {
                        sig = GetOrComputeLayoutSig(L);
                        std::lock_guard<std::mutex> _l(g_mx);
                        g_sigCacheByClass[cls][id] = sig;
                    }
                }
                if (sig && g_targetLayoutSigs.count(sig))
                {
                    outId = id;
                    outSig = sig;
                    return true;
                }
            }
            return false;
        }

        // Pick the best class we’ve seen that exposes a target layout.
        static void* PickClassByTargetLayout(uint64_t& outLayoutId, uint64_t& outSig)
        {
            for (void* wf : g_seenWindowFunctions) {
                uint64_t id=0,sig=0;
                if (FindMatchingLayoutInClass(wf, id, sig) && g_targetLayoutSigs.count(sig)) {
                    outLayoutId=id; outSig=sig; return wf;
                }
            }
            return nullptr;
        }


        // -----------------------------------------------------------------------------
        // WINDOW ROUTE
        // -----------------------------------------------------------------------------

        // Read the "parent component" and "port" that Window::AddChild uses for NodeConnectShim
        static bool GetWindowGraphPort(void* window, void*& outParentComp, const void*& outPort)
        {
            if (!window) return false;
            void* parentComp = nullptr;
            const void* port = nullptr;
            bool ok = Seh("GetWindowGraphPort", window, [&]
            {
                parentComp = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(window) + 0x28);
                if (parentComp)
                {
                    port = reinterpret_cast<const void*>(reinterpret_cast<uint8_t*>(parentComp) + 0x60);
                }
            });
            if (!ok || !parentComp || !port) return false;
            outParentComp = parentComp;
            outPort = port;
            return true;
        }

        // Choose a parent window to host our own window under.
        static void* PickParentWindow()
        {
            std::lock_guard<std::mutex> _l(g_mx);
            if (g_knownParentWindows.empty()) return nullptr;
            // Heuristic: first seen is usually the main “HUD/root-ish” parent (good enough to begin).
            return *g_knownParentWindows.begin();
        }

        // Create our UiModelText node with a *valid* creation context.
        static void* CreateSafeTextNode()
        {
            void* cc = g_lastTextCreationCtx.load(std::memory_order_relaxed);
            uint32_t sc = g_lastTextSceneStr.load(std::memory_order_relaxed);
            void* node = nullptr;

            if (cc)
            {
                node = NewUiModelText(sc, cc, nullptr, nullptr);
                if (!node) spdlog::warn("[WIN] NewUiModelText(cc) returned null; will try nullptr ctx as fallback.");
            }
            if (!node) node = NewUiModelText(0, nullptr, nullptr, nullptr);

            if (!node)
            {
                spdlog::warn("[WIN] NewUiModelText failed (cc={} sc=0x{:08X})", cc, sc);
                return nullptr;
            }
            {
                std::lock_guard<std::mutex> _l(g_mx);
                g_ourNodes.insert(node);
            }
            return node;
        }

        static bool GetWindowGraphPortSafe(void* w, void*& parentComp, const void*& port)
        {
            parentComp = nullptr;
            port = nullptr;
            bool ok = Seh("GetWindowGraphPort", w, [&]
            {
                parentComp = *(void**)((uint8_t*)w + 0x28);
                if (parentComp) port = (const void*)((uint8_t*)parentComp + 0x60);
            });
            if (!ok || !parentComp || !port) return false;

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(parentComp, &mbi, sizeof(mbi)) != sizeof(mbi) || !(mbi.State & MEM_COMMIT)) return false;
            if (VirtualQuery(port, &mbi, sizeof(mbi)) != sizeof(mbi) || !(mbi.State & MEM_COMMIT)) return false;
            return true;
        }

        // Update per-layout "current" signature using the model we just validated
        static uint64_t UpdateCurrentLayoutSig(void* layout, void* model)
        {
            const uint64_t s = ComputeLayoutSigFromModel(model);
            {
                std::lock_guard<std::mutex> _l(g_mx);
                g_sigByModel[model] = s;
                g_currentSigByLayout[layout] = s;
            }

            // NEW: ensure we have an anchor for this layout and bind it to the sig
            std::pair<void*, const void*> a{};
            {
                std::lock_guard<std::mutex> _l(g_mx);
                auto it = g_anchorForLayout.find(layout);
                if (it != g_anchorForLayout.end()) a = it->second;
            }
            if (!a.first || !a.second)
            {
                // try to resolve immediately (safe, uses common[] port)
                TryResolveAnchorForLayout(layout, a);
            }
            if (a.first && a.second)
            {
                std::lock_guard<std::mutex> _l(g_mx);
                if (!g_anchorBySig.count(s))
                {
                    g_anchorBySig[s] = a;
                    spdlog::info("[SIG] bind anchorBySig: sig=0x{:016X} parent={} port={}", s, a.first, a.second);
                }
            }
            return s;
        }

        static bool ValidateAnchor(void* parentComp, const void* portPtr)
        {
            if (!parentComp || !portPtr) return false;
            const void* expected = (const void*)((uint8_t*)parentComp + 0x60);
            if (expected != portPtr) {
                spdlog::warn("[ANCHOR] portPtr mismatch: expected={} got={}", expected, portPtr);
                return false;
            }
            // Optional: also ensure the field currently points to something (not required)
            // void* val = *(void**)expected; if (!val) spdlog::warn("[ANCHOR] field value is null");
            return true;
        }

        // Try to inject directly into the currently visible target layout via an already learned anchor
        static bool TryInjectViaAnchorBySig()
        {
            // Prefer an anchor for the *currently visible* target sig
            uint64_t activeSig = 0;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                for (auto& kv : g_currentSigByLayout)
                {
                    if (g_targetLayoutSigs.count(kv.second))
                    {
                        activeSig = kv.second;
                        break;
                    }
                }
            }

            std::pair<void*, const void*> anchor{};
            {
                std::lock_guard<std::mutex> _l(g_mx);
                if (activeSig && g_anchorBySig.count(activeSig))
                    anchor = g_anchorBySig[activeSig];
                else
                {
                    // fallback: any target sig we’ve learned an anchor for
                    for (auto s : g_targetLayoutSigs)
                    {
                        auto it = g_anchorBySig.find(s);
                        if (it != g_anchorBySig.end())
                        {
                            anchor = it->second;
                            activeSig = s;
                            break;
                        }
                    }
                }
            }

            if (!anchor.first || !anchor.second) return false;

            if (!ValidateAnchor(anchor.first, anchor.second))
            {
                spdlog::warn("[INJECT] anchorBySig invalid; skipping NodeConnectShim.");
                return false;
            }

            void* pField = (void*)((uint8_t*)anchor.first + 0x60);
            spdlog::info("[INJECT] parent+0x60(field)={} match={}", pField, (pField == anchor.second));

            spdlog::info("[INJECT] candidates in anchorBySig: {}", g_anchorBySig.size());
            spdlog::info("[INJECT] activeSig=0x{:016X}", activeSig);

            void* child = CreateSafeTextNode();
            if (!child) return false;

            uint8_t* parent = static_cast<uint8_t*>(anchor.first);
            void* fieldAddr = parent ? (parent + 0x60) : nullptr;
            void* portNode  = nullptr;
            Seh("read portNode", fieldAddr, [&]{ portNode = *(void**)fieldAddr; });

            bool ok = false;

            // A) Most layout connects we observed use the *value* (node) form
            if (portNode) {
                ok = Seh("Connect(node-value)", child, [&]{
                    NodeConnectShim(child, anchor.first, portNode);
                });
            }

            // B) Fallback: some paths (e.g., ConnectWindowToParent) pass the *field address*
            if (!ok && fieldAddr) {
                ok = Seh("Connect(field-addr)", child, [&]{
                    NodeConnectShim(child, anchor.first, fieldAddr);
                });
            }

            if (!ok) return false;

            // Styling stays the same
            if (auto** pp = GetGlobalUixUtility())
                if (void* uix = *pp) {
                    UpdateTextForNode(uix, child);
                    SetModelNodePriority(uix, child, 240);
                    SetModelNodeTextFontSize(uix, child, 28.0f, 0.0f);
                    SetModelNodeTextColorRGB(uix, child, 1.0f, 1.0f, 1.0f);
                }

            spdlog::info("[INJECT] via anchorBySig ok.");
            return true;
        }

        static bool CreateOurWindowAndInjectText()
        {
            if (g_myWindow.load())
            {
                spdlog::info("[WIN] Already created: {}", g_myWindow.load());
                return true;
            }
            if (!g_lastTextCreationCtx.load())
            {
                spdlog::warn("[WIN] No ModelNodeText creation context harvested yet. Touch HUD/menu, then F7.");
                return false;
            }

            // 0) Best case: inject right into the live layout we already learned an anchor for
            if (TryInjectViaAnchorBySig()) return true;

            // 1) Window route only if we can actually find a class exposing a matching target sig
            uint64_t layoutId = UINT64_MAX, layoutSig = 0;
            void* cls = PickClassByTargetLayout(layoutId, layoutSig);
            if (!cls)
            {
                spdlog::warn(
                    "[WIN] No WindowFunction with a target sig in cache yet; keep the target UI visible briefly and try again.");
                return false; // <-- do NOT fall back to last-seen class; that was your crash path
            }
            spdlog::info("[WIN] Selected class={} matching layoutId={} sig64=0x{:016X}", cls, layoutId, layoutSig);

            // 2) Parent to host under (we only use parents we actually observed)
            void* parentWin = PickParentWindow();
            if (!parentWin)
            {
                spdlog::warn("[WIN] No candidate parent window observed yet.");
                return false;
            }

            // 3) Create the instance and attach
            void* myWin = CreateNewWindow(cls, nullptr, 0, 0);
            if (!myWin)
            {
                spdlog::warn("[WIN] CreateNewWindow failed for class={}", cls);
                return false;
            }
            AddChildWindow(parentWin, myWin);
            spdlog::info("[WIN] Created {} and added under {}", myWin, parentWin);

            // 4) Resolve graph port safely
            void* parentComp = nullptr;
            const void* port = nullptr;
            if (!GetWindowGraphPortSafe(myWin, parentComp, port))
            {
                spdlog::warn("[WIN] Couldn’t get a valid graph port from our window; aborting.");
                return false;
            }

            // 5) Make text and connect
            void* node = CreateSafeTextNode();
            if (!node) return false;

            bool ok = Seh("Connect(our text -> our window)", node, [&]
            {
                NodeConnectShim(node, parentComp, const_cast<void*>(port));
            });
            if (!ok) return false;

            if (auto** pp = GetGlobalUixUtility())
                if (void* uix = *pp)
                {
                    UpdateTextForNode(uix, node);
                    SetModelNodePriority(uix, node, 240);
                    SetModelNodeTextFontSize(uix, node, 28.0f, 0.0f);
                    SetModelNodeTextColorRGB(uix, node, 1.0f, 1.0f, 1.0f);
                }

            g_myWindow.store(myWin);
            g_myTextNode.store(node);
            spdlog::info("[WIN] Injected node={} into window={} (parentComp={} port={})", node, myWin, parentComp,
                         port);
            return true;
        }

        // -----------------------------------------------------------------------------
        // Injection for legacy layout path (kept for reference; not used by F7 now)
        // -----------------------------------------------------------------------------
        static size_t Inject_AllAnchoredLayouts()
        {
            void** ppUix = GetGlobalUixUtility();
            void* uix = ppUix ? *ppUix : nullptr;
            if (!uix)
            {
                spdlog::warn("[ROOT] UIX utility not available; aborting inject.");
                return 0;
            }
            size_t newlyAnchored = ResolveAnchors_AllLayouts();
            if (newlyAnchored) spdlog::info("[ROOT] newly resolved anchors: {}", newlyAnchored);

            std::vector<void*> layouts;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                for (auto& L : g_knownLayouts) layouts.push_back(L);
            }

            size_t injected = 0;
            for (void* layout : layouts)
            {
                std::pair<void*, const void*> anchor{};
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    if (g_injectedNodeByLayout.count(layout)) continue;
                    auto it = g_anchorForLayout.find(layout);
                    if (it == g_anchorForLayout.end() || !it->second.first || !it->second.second)
                    {
                        spdlog::info("[ROOT] layout={} no safe anchor yet; skip.", layout);
                        continue;
                    }
                    anchor = it->second;
                }

                // Create text node using harvested ctx (safer than nullptr ctx).
                void* node = CreateSafeTextNode();
                if (!node) continue;

                bool ok = Seh("NodeConnectShim(layout)", node, [&]
                {
                    NodeConnectShim(node, anchor.first, const_cast<void*>(anchor.second));
                });
                if (!ok)
                {
                    spdlog::warn("[ROOT] NodeConnectShim failed; layout={} node={}", layout, node);
                    continue;
                }

                bool vis = false;
                if (uix)
                {
                    vis = IsNodeVisible(uix, node);
                    RememberVis(node, vis);
                    UpdateTextForNode(uix, node);
                    SetModelNodePriority(uix, node, 240);
                    SetModelNodeTextFontSize(uix, node, 28.0f, 0.0f);
                    SetModelNodeTextColorRGB(uix, node, 1.0f, 1.0f, 1.0f);
                }

                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    g_injectedNodeByLayout[layout] = node;
                    g_layoutsByNode.emplace(node, layout);
                }
                spdlog::info("[ROOT] injected: layout={} node={} parent={} port={} vis={}",
                             layout, node, anchor.first, anchor.second, vis ? "T" : "F");
                ++injected;
            }
            return injected;
        }

        static void DumpSigState()
        {
            std::lock_guard<std::mutex> _l(g_mx);

            // 1) Current per-layout sigs (what’s visible now)
            spdlog::info("[SIG] ---- Current Sig By Layout ({} entries) ----", g_currentSigByLayout.size());
            for (const auto& kv : g_currentSigByLayout)
            {
                void* layout = kv.first;
                uint64_t sig = kv.second;
                const char* label =
                    (sig == 0x6E6A53858C7D348Aull)
                        ? "MainMenu"
                        : (sig == 0xF9325CE34EBD7F47ull)
                        ? "HUD"
                        : (sig == 0x74E5E1FF080986D1ull)
                        ? "iDroid"
                        : "";
                spdlog::info("[SIG] layout={} sig64=0x{:016X} {}", layout, sig, label);
            }

            // 2) Anchors learned per sig (what’s injectable right now via TryInjectViaAnchorBySig)
            spdlog::info("[ANCHOR] ---- anchorBySig ({} entries) ----", g_anchorBySig.size());
            for (const auto& kv : g_anchorBySig)
            {
                uint64_t sig = kv.first;
                void* parent = kv.second.first;
                const void* port = kv.second.second;
                const char* label =
                    (sig == 0x6E6A53858C7D348Aull)
                        ? "MainMenu"
                        : (sig == 0xF9325CE34EBD7F47ull)
                        ? "HUD"
                        : (sig == 0x74E5E1FF080986D1ull)
                        ? "iDroid"
                        : "";
                spdlog::info("[ANCHOR] sig64=0x{:016X} parent={} port={} {}", sig, parent, port, label);
            }

            // 3) Optional: models per layout (helps confirm why one layout ptr shows multiple sigs)
            spdlog::info("[MODEL] ---- modelsOfLayout ({} layouts) ----", g_modelsOfLayout.size());
            for (const auto& kv : g_modelsOfLayout)
            {
                void* layout = kv.first;
                const auto& models = kv.second;
                spdlog::info("[MODEL] layout={} models={}", layout, models.size());
                for (auto m : models)
                {
                    uint64_t ms = 0;
                    auto it = g_sigByModel.find(m);
                    if (it != g_sigByModel.end()) ms = it->second;
                    spdlog::info("         model={} sig64=0x{:016X}", m, ms);
                }
            }
        }

        static void DumpInjected()
        {
            void** ppUix = GetGlobalUixUtility();
            void* uix = ppUix ? *ppUix : nullptr;

            // Our window
            spdlog::info("[WIN] ===== Our Window Status =====");
            void* myWin = g_myWindow.load();
            void* myText = g_myTextNode.load();
            if (myWin)
            {
                void* pc = nullptr;
                const void* pt = nullptr;
                GetWindowGraphPort(myWin, pc, pt);
                char v = '?';
                if (uix && myText)
                {
                    bool b = IsNodeVisible(uix, myText);
                    RememberVis(myText, b);
                    v = b ? 'T' : 'F';
                }
                std::string text;
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    auto tt = g_textByNode.find(myText);
                    if (tt != g_textByNode.end()) text = tt->second;
                }
                spdlog::info("ourWindow={} parentComp={} port={} textNode={} vis={} text={}",
                             myWin, pc, pt, myText, v, text.empty() ? "\"\"" : fmt::format("\"{}\"", text));
            }
            else
            {
                spdlog::info("ourWindow=<none>");
            }

            // Legacy layout
            spdlog::info("[ROOT] ===== Layout Injection Status ({} layouts) =====", g_injectedNodeByLayout.size());
            for (auto& kv : g_injectedNodeByLayout)
            {
                void* layout = kv.first;
                void* node = kv.second;
                void* parent = nullptr;
                const void* port = nullptr;

                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    auto it = g_anchorForLayout.find(layout);
                    if (it != g_anchorForLayout.end())
                    {
                        parent = it->second.first;
                        port = it->second.second;
                    }
                }

                char v = '?';
                if (uix && node)
                {
                    bool b = IsNodeVisible(uix, node);
                    RememberVis(node, b);
                    v = b ? 'T' : 'F';
                }
                std::string text;
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    auto tt = g_textByNode.find(node);
                    if (tt != g_textByNode.end()) text = tt->second;
                }

                spdlog::info("layout={} parent={} port={} node={} vis={} text={}",
                             layout, parent, port, node, v,
                             text.empty() ? "\"\"" : fmt::format("\"{}\"", text));
            }

            {
                std::lock_guard<std::mutex> _l(g_mx);
                spdlog::info("[SIG] ===== Known Layout Signatures ({} total) =====", g_sigByLayout.size());
                for (auto& kv : g_sigByLayout)
                {
                    const bool isTarget = g_targetLayoutSigs.count(kv.second) != 0;
                    // if (!kv.first || kv.second == 0) continue;
                    // if (g_knownLayouts.count(kv.first) == 0) continue;
                    spdlog::info("[SIG] layout={} sig64=0x{:016X}{}", kv.first, kv.second,
                                 isTarget ? "  <TARGET>" : "");
                }
                spdlog::info("[SIG] ==============================================");
            }

            DumpSigState();

            spdlog::info("[ROOT] =========================================");
        }


        // -----------------------------------------------------------------------------
        // Hotkeys
        // -----------------------------------------------------------------------------
        static bool JustPressed(int vk)
        {
            static SHORT prev[256] = {};
            SHORT s = GetAsyncKeyState(vk);
            bool downNow = (s & 0x8000) != 0;
            bool downPrev = (prev[vk] & 0x8000) != 0;
            prev[vk] = s;
            return downNow && !downPrev;
        }

        static void PollHotkeys()
        {
            if (JustPressed(VK_F7))
            {
                spdlog::warn("[HK] F7 -> Create our window + inject UiModelText");
                bool injected = TryInjectViaAnchorBySig();
                if (!injected) injected = CreateOurWindowAndInjectText();
                spdlog::info("[WIN] F7 result: {}", injected ? "OK" : "FAILED");
            }
            if (JustPressed(VK_F8))
            {
                spdlog::info("[HK] F8 -> dump status");
                DumpInjected();
            }
            if (JustPressed(VK_F9))
            {
                spdlog::info("[HK] F9 -> dump common ports for known layouts");
                std::vector<void*> layouts;
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    for (auto& L : g_knownLayouts) layouts.push_back(L);
                }
                for (void* L : layouts) DumpCommonPortsForLayout(L);
            }
            if (JustPressed(VK_F10))
            {
                spdlog::info("[HK] F10 -> resolve layout anchors");
                size_t n = ResolveAnchors_AllLayouts();
                // NEW: propagate anchors to sigs we’ve seen
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    for (auto& kv : g_currentSigByLayout)
                    {
                        void* layout = kv.first;
                        uint64_t sig = kv.second;
                        auto it = g_anchorForLayout.find(layout);
                        if (!sig)
                        {
                            // no visible sig for this layout now
                            continue;
                        }
                        if (it == g_anchorForLayout.end())
                        {
                            spdlog::warn("[SIG] F10: layout={} has no anchor yet; skipping bind.", layout);
                            continue;
                        }

                        const auto& a = it->second;
                        if (a.first == layout || !a.first || !a.second)
                        {
                            spdlog::warn("[SIG] F10 NOT bound for sig=0x{:016X} (parent was layout or null).", sig);
                            continue;
                        }

                        // Optional: validate before binding
                        if (!ValidateAnchor(a.first, a.second))
                        {
                            spdlog::warn("[SIG] F10 anchor failed validation for sig=0x{:016X}.", sig);
                            continue;
                        }

                        g_anchorBySig[sig] = a;
                        spdlog::info("[SIG] F10 bound sig=0x{:016X} -> (parentComp={},port={})", sig, a.first,
                                     a.second);
                    }
                }
                spdlog::info("[ROOT] anchors resolved: {}", n);
            }
        }

        static void BindAnchorToActiveSig(void* parentComp, void* portPtr) {
            if (!parentComp || !portPtr) return;
            // sanity: parent->+0x60 must equal port
            void* p60 = nullptr;
            Seh("parent+0x60", parentComp, [&]{ p60 = *(void**)((uint8_t*)parentComp + 0x60); });
            if (p60 != portPtr) return;

            uint64_t sig = 0;
            {   // choose the currently visible target sig if unique
                std::lock_guard<std::mutex> _l(g_mx);
                for (auto& kv : g_currentSigByLayout) {
                    if (g_targetLayoutSigs.count(kv.second)) { sig = kv.second; break; }
                }
            }
            if (!sig) return;

            std::lock_guard<std::mutex> _l(g_mx);
            if (!g_anchorBySig.count(sig)) {
                g_anchorBySig[sig] = { parentComp, portPtr };
                spdlog::info("[ANCHOR] learned via ConnectComponent: sig=0x{:016X} parent={} port={}", sig, parentComp, portPtr);
            }
        }

        // -----------------------------------------------------------------------------
        // Hooks
        // -----------------------------------------------------------------------------

        // text hooks
        void __fastcall SetTextForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, const char* rawText,
                                                    bool isLocalized)
        {
            if (rawText && *rawText) RememberText(nodeText, rawText);
            SetTextForModelNodeText(uix, nodeText, textUnit, rawText, isLocalized);
        }

        void __fastcall SetTextUnitsForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, uint64_t unitId)
        {
            RememberSid(nodeText, unitId);
            SetTextUnitsForModelNodeText(uix, nodeText, textUnit, unitId);
        }

        bool __fastcall SetTextUnitsHook(void* nodeText, void* textUnit, uint64_t stringId)
        {
            RememberSid(nodeText, stringId);
            return SetTextUnits(nodeText, textUnit, stringId);
        }

        // visibility hooks
        void __fastcall SetNodeVisibilityWrapperHook(void* anyMgr, void* node, bool visible)
        {
            RememberVis(node, visible);
            SetNodeVisibilityWrapper(anyMgr, node, visible);
        }

        void __fastcall SetNodeVisibilityHook(void* node, bool visible)
        {
            RememberVis(node, visible);
            SetNodeVisibility(node, visible);
        }

        bool __fastcall IsNodeVisibleHook(void* anyMgr, void* node)
        {
            bool v = IsNodeVisible(anyMgr, node);
            RememberVis(node, v);
            return v;
        }


        // wiring (learn anchors from live connects)
        void __fastcall NodeConnectShimHook(void* childComp, void* parentComp, void* port)
        {
            const bool ours = [&]{ std::lock_guard<std::mutex> _l(g_mx); return g_ourNodes.count(childComp)!=0; }();
            if (!ours) BindAnchorToActiveSig(parentComp, port);
            NodeConnectShim(childComp, parentComp, port);
        }

        // model discovery (layouts)
        void* __fastcall GetModelWrapperHook(void* layout, void** outModel, uint32_t wantRoot)
        {
            void* ret = GetModelWrapper(layout, outModel, wantRoot);

            void* model = nullptr;
            if (ret && GetModelNodeFromIndex(ret, 0)) model = ret;
            else if (outModel)
            {
                void* out = nullptr;
                Seh("GMw.outModel.read", outModel, [&] { out = *outModel; });
                if (out && GetModelNodeFromIndex(out, 0)) model = out;
            }

            if (model)
            {
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    g_knownLayouts.insert(layout);
                    g_layoutByModel[model] = layout;
                    g_primaryModelByLayout[layout] = model;
                    g_modelsOfLayout[layout].insert(model);
                }

                EnumerateModelNodes(model, layout, 4096);
                const uint64_t mSig = UpdateCurrentLayoutSig(layout, model);

                spdlog::info("[GMw] layout={} model={} wantRoot={} modelSig=0x{:016X}",
                             layout, model, wantRoot, mSig);
            }
            return ret;
        }

        void* __fastcall GetModelNodeFromIndexHook(const void* model, int index)
        {
            return GetModelNodeFromIndex(model, index);
        }

        void* __fastcall GetModelNodeCommonHook(void* selfModel)
        {
            return GetModelNodeCommon(selfModel);
        }

        void* __fastcall GetModelNodeCommonInternalHook(void* selfModel, uint64_t sid)
        {
            return GetModelNodeCommonInternal(selfModel, sid);
        }

        bool __fastcall IsHaveModelNodeCommonHook(void* selfUixUtility, const void* model, uint64_t stringId)
        {
            return IsHaveModelNodeCommon(selfUixUtility, model, stringId);
        }

        // lifecycle
        void __fastcall OnLayoutComponentDestroyHook(void* self)
        {
            {
                std::lock_guard<std::mutex> _l(g_mx);

                // Drop any layout whose anchor parentComp == self
                for (auto it = g_anchorForLayout.begin(); it != g_anchorForLayout.end(); ) {
                    if (it->second.first == self) {
                        g_injectedNodeByLayout.erase(it->first);
                        it = g_anchorForLayout.erase(it);
                    } else ++it;
                }

                // Drop any sig-bound anchor using this parentComp
                for (auto it = g_anchorBySig.begin(); it != g_anchorBySig.end(); ) {
                    if (it->second.first == self) it = g_anchorBySig.erase(it);
                    else ++it;
                }
            }
            OnLayoutComponentDestroy(self);
        }

        // creation ctx harvester
        void* __fastcall NewUiModelTextHook(uint32_t sceneStrCode32, void* creationCtx, void* opt0, void* opt1)
        {
            // Harvest a known-good ctx + scene code for later self-spawned text.
            if (creationCtx) g_lastTextCreationCtx.store(creationCtx, std::memory_order_relaxed);
            if (sceneStrCode32) g_lastTextSceneStr.store(sceneStrCode32, std::memory_order_relaxed);
            return NewUiModelText(sceneStrCode32, creationCtx, opt0, opt1);
        }

        // window plumbing hooks
        void __fastcall UpdateWindowGraphHook(void* selfWindow)
        {
            UpdateWindowGraph(selfWindow);
        }

        void __fastcall AddChildWindowHook(void* selfWindow, void* childWindow)
        {
            // Remember parents we see in real connects — useful as “root-ish” hosts.
            if (selfWindow)
            {
                std::lock_guard<std::mutex> _l(g_mx);
                g_knownParentWindows.insert(selfWindow);
            }
            AddChildWindow(selfWindow, childWindow);
        }

        void* __fastcall CreateNewWindowHook(void* cls /*WindowFunction*/, const void* nameStr, uint32_t flagsA,
                                             uint32_t flagsB)
        {
            if (cls)
            {
                g_lastWindowFunctionClass.store(cls, std::memory_order_relaxed);
                std::lock_guard<std::mutex> _l(g_mx);
                g_seenWindowFunctions.insert(cls);
            }
            return CreateNewWindow(cls, nameStr, flagsA, flagsB);
        }

        void* __fastcall GetWindowManagerHook()
        {
            return GetWindowManager();
        }

        void* __fastcall GetWindowLayoutHook(void* windowFunction, uint64_t layoutId)
        {
            void* L = GetWindowLayout(windowFunction, layoutId);
            spdlog::info("GetWindowLayoutHook: ret layout={} params windowFunction={} layoutId={}",
                         L, windowFunction, layoutId);
            if (L)
            {
                uint64_t sig = 0;
                {
                    // prefer the current sig we already tracked for this layout
                    std::lock_guard<std::mutex> _l(g_mx);
                    auto it = g_currentSigByLayout.find(L);
                    if (it != g_currentSigByLayout.end()) sig = it->second;
                }
                if (!sig) sig = GetOrComputeLayoutSig(L); // fallback if we have a model captured
                spdlog::info("GetWindowLayoutHook: ... sig64=0x{:016X}", sig);

                std::lock_guard<std::mutex> _l(g_mx);
                g_sigCacheByClass[windowFunction][layoutId] = sig;
            }
            return L;
        }

        void* __fastcall FindWindowFactoryHook(void* collector, int hash)
        {
            return FindWindowFactory(collector, hash);
        }

        // vtbl[1] (offset +0x8) appears to be the GetId() returning the 32-bit hash used in FindWindowFactory
        static int ReadFactoryId(void* factory)
        {
            if (!factory) return 0;
            auto** vtbl = *reinterpret_cast<void***>(factory);
            using GetIdFn = int(__fastcall*)(void*);
            return ((GetIdFn)vtbl[1])(factory);
        }

        void __fastcall RegisterWindowFactoryHook(void* collector, void* factory)
        {
            // capture id->factory mapping
            int id = 0;
            Seh("Factory.GetId", factory, [&] { id = ReadFactoryId(factory); });
            if (id)
            {
                std::lock_guard<std::mutex> _l(g_mx);
                g_factoryById[id] = factory;
            }
            RegisterWindowFactory(collector, factory);
        }

        void* __fastcall GetWindowHandleHook(void* mgr, void* windowFunction)
        {
            return GetWindowHandle(mgr, windowFunction);
        }

        void __fastcall SetLayoutInfoHook(void* windowHandle, const void* layoutInfo)
        {
            SetLayoutInfo(windowHandle, layoutInfo);
        }

        void* __fastcall GetTextUnitsHook(int index)
        {
            return GetTextUnits(index);
        }

        void __fastcall SetTextUnitHook(void* selfTextUnit, char* text, uint32_t flags, uint16_t p3, uint16_t p4,
                                        float size, float tracking, uint32_t p7, uint32_t p8)
        {
            SetTextUnit(selfTextUnit, text, flags, p3, p4, size, tracking, p7, p8);
        }

        void __fastcall GraphUpdateHook(void* selfGraph)
        {
            GraphUpdate(selfGraph);
        }

        void* __fastcall GetUixLayoutHook(void* manager, const void* windowIface, uint64_t layoutId)
        {
            auto layout = GetUixLayout(manager, windowIface, layoutId);
            spdlog::info("GetUixLayoutHook: ret layout={} params manager={} windowIface={} layoutId={}",
                         layout, manager, windowIface, layoutId);
            if (layout)
            {
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    g_knownLayouts.insert(layout);
                }
                GetOrComputeLayoutSig(layout);
            }
            return layout;
        }

        void __fastcall ConnectLayoutComponentHook(void* childComp, void* parentComp, void* portPtr)
        {
            BindAnchorToActiveSig(parentComp, portPtr);
            ConnectLayoutComponent(childComp, parentComp, portPtr);
        }

         void __fastcall ConnectLayoutUtilityComponentHook(void* childComp, void* parentComp, uint32_t portSid)
        {
            ConnectLayoutUtilityComponent(childComp, parentComp, portSid);
        }

        void __fastcall ConnectChildWindowToNodeHook(void* window, void* windowHandle, void* parentComp, void* portPtr)
        {
            void* p60=nullptr; Seh("parent+0x60", parentComp, [&]{ p60 = *(void**)((uint8_t*)parentComp + 0x60); });
            spdlog::debug("[WCN] parent={} port={} parent+0x60={} match={}", parentComp, portPtr, p60, (p60==portPtr));
            ConnectChildWindowToNode(window, windowHandle, parentComp, portPtr);
        }

        void __fastcall ConnectWindowToParentHook(void* windowFunction, void* parentComp, void* portPtr)
        {
            ConnectWindowToParent(windowFunction, parentComp, portPtr);
            void* p60 = *(void**)((uint8_t*)parentComp + 0x60);
            spdlog::info("[WCN] parent={} port={} parent+0x60={} match={}",
                         parentComp, portPtr, p60, (p60==portPtr));
        }
        
         void __fastcall LayoutConnectHook(void* uiUtil, void* windowIface, uint64_t sidA, uint64_t sidB, uint64_t sidModel, uint64_t sidPort)
        {
            spdlog::debug("[LAYOUTCONNECT] wi={} sA=#{:08X} sB=#{:08X} sModel=#{:08X} sPort=#{:08X}",
                          windowIface, (uint32_t)sidA, (uint32_t)sidB, (uint32_t)sidModel, (uint32_t)sidPort);
            LayoutConnect(uiUtil, windowIface, sidA, sidB, sidModel, sidPort);
        }
        
        // frame/update
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);
            MaybeRefreshInjectedText();
            PollHotkeys();
        }

        // -----------------------------------------------------------------------------
        // Install
        // -----------------------------------------------------------------------------
        void CreateHooks()
        {
            spdlog::set_level(spdlog::level::debug);

            CREATE_HOOK(SetTextForModelNodeText)
            CREATE_HOOK(SetTextUnitsForModelNodeText)
            CREATE_HOOK(SetTextUnits)

            CREATE_HOOK(SetNodeVisibilityWrapper)
            CREATE_HOOK(SetNodeVisibility)
            CREATE_HOOK(IsNodeVisible)

            CREATE_HOOK(NodeConnectShim)
            CREATE_HOOK(NewUiModelText)

            CREATE_HOOK(GetModelWrapper)
            CREATE_HOOK(GetModelNodeFromIndex)

            CREATE_HOOK(GetModelNodeCommon)
            CREATE_HOOK(GetModelNodeCommonInternal)
            CREATE_HOOK(IsHaveModelNodeCommon)

            CREATE_HOOK(OnLayoutComponentDestroy)

            CREATE_HOOK(UpdatePhaseUi)
            
            // Window route
            CREATE_HOOK(UpdateWindowGraph)
            CREATE_HOOK(AddChildWindow)
            CREATE_HOOK(CreateNewWindow)
            CREATE_HOOK(GetWindowManager)
            CREATE_HOOK(GetWindowLayout)

            CREATE_HOOK(FindWindowFactory)
            // CREATE_HOOK(RegisterWindowFactory) Crashes
            CREATE_HOOK(GetWindowHandle)
            CREATE_HOOK(SetLayoutInfo)
            CREATE_HOOK(GetTextUnits)
            CREATE_HOOK(SetTextUnit)
            CREATE_HOOK(GraphUpdate)
            CREATE_HOOK(GetUixLayout)
            
            CREATE_HOOK(ConnectLayoutComponent)
            CREATE_HOOK(ConnectLayoutUtilityComponent)
            CREATE_HOOK(ConnectChildWindowToNode)
            CREATE_HOOK(ConnectWindowToParent)
            CREATE_HOOK(LayoutConnect)

            //-------------------ENABLE-------------------------

            ENABLEHOOK(SetTextForModelNodeText)
            ENABLEHOOK(SetTextUnitsForModelNodeText)
            ENABLEHOOK(SetTextUnits)

            ENABLEHOOK(SetNodeVisibilityWrapper)
            ENABLEHOOK(SetNodeVisibility)
            ENABLEHOOK(IsNodeVisible)

            ENABLEHOOK(NodeConnectShim)
            ENABLEHOOK(NewUiModelText)

            ENABLEHOOK(GetModelWrapper)
            ENABLEHOOK(GetModelNodeFromIndex)

            ENABLEHOOK(GetModelNodeCommon)
            ENABLEHOOK(GetModelNodeCommonInternal)
            ENABLEHOOK(IsHaveModelNodeCommon)

            ENABLEHOOK(OnLayoutComponentDestroy)

            ENABLEHOOK(UpdatePhaseUi)

            // Window route
            ENABLEHOOK(UpdateWindowGraph)
            ENABLEHOOK(AddChildWindow)
            ENABLEHOOK(CreateNewWindow)
            ENABLEHOOK(GetWindowManager)
            ENABLEHOOK(GetWindowLayout)

            ENABLEHOOK(FindWindowFactory)
            // ENABLEHOOK(RegisterWindowFactory) Crashes
            ENABLEHOOK(GetWindowHandle)
            ENABLEHOOK(SetLayoutInfo)
            ENABLEHOOK(GetTextUnits)
            ENABLEHOOK(SetTextUnit)
            ENABLEHOOK(GraphUpdate)
            ENABLEHOOK(GetUixLayout)

            ENABLEHOOK(ConnectLayoutComponent)
            ENABLEHOOK(ConnectLayoutUtilityComponent)
            ENABLEHOOK(ConnectChildWindowToNode)
            ENABLEHOOK(ConnectWindowToParent)
            ENABLEHOOK(LayoutConnect)

            spdlog::info("[UI-HOOK] Hooks installed (Window route on F7; layout route retained for debugging).");
        }

        // Optional Lua glue placeholders
        int l_PrintViewTree(lua_State* L) { return 0; }

        int CreateLibs(lua_State* L)
        {
            spdlog::debug(__func__);
            luaL_Reg libFuncs[] = {
                {"PrintViewTree", l_PrintViewTree},
                {NULL, NULL}
            };
            luaI_openlib(L, "IhkUI", libFuncs, 0);
            return 1;
        }
    } // namespace Hooks_Ui
} // namespace IHHook
