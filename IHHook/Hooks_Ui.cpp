// Hooks_Ui.cpp — ROOT injector using fox::ui::Model::GetModelNodeCommon (F7/F8/F10)
//
// Hotkeys:
//   F7  -> Inject "Camo: N" into every layout that has an anchor
//   F8  -> Dump injection status (layout/parent/port/node/visible/text)
//   F10 -> Resolve anchors for all known layouts (calls IsHaveModelNodeCommon + GetModelNodeCommonInternal)
//
// Notes:
//  • Parent component = layout pointer; Port node = model->GetModelNodeCommonInternal(model, ROOT_SID) if present,
//    else model->GetModelNodeCommon() as fallback.
//  • We only probe when UI is live (hotkey path / UpdatePhaseUi).
//  • Once-per-layout injection; discovery is SEH-guarded.
//
// Requires in mgsvtpp_func_typedefs.h (or equivalent):
//   void*  __fastcall GetModelWrapper(void* layout, void* outModel, uint32_t outRoot);
//   void*  __fastcall GetModelNodeFromIndex(const void* model, int index);
//   void*  __fastcall NewUiModelText(uint32_t, void*, void*, void*);
//   void   __fastcall SetTextForModelNodeText(void* uix, void* nodeText, void* textUnit, const char* text, bool isLoc);
//   void   __fastcall SetModelNodePriority(void* uix, void* node, int prio);
//   void   __fastcall SetModelNodeTextFontSize(void* uix, void* node, float size, float tracking);
//   void   __fastcall SetModelNodeTextColorRGB(void* uix, void* node, float r, float g, float b);
//   bool   __fastcall IsNodeVisible(void* anyMgr, void* node);
//   void*  __fastcall GetModelNodeCommon(void* selfModel);                     // 1-arg vfunc
//   void*  __fastcall GetModelNodeCommonInternal(void* selfModel, uint32_t);   // SID variant
//   bool   __fastcall IsHaveModelNodeCommon(void* uixUtil, const void* model, uint64_t sid);
//   void   __fastcall NodeConnectShim(void* node, void* parentComp, void* portNode);
//   void** GetGlobalUixUtility();
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
        // -----------------------------------------------------------------------------//
        // Globals / state
        // -----------------------------------------------------------------------------//
        static std::mutex g_mx;

        static std::unordered_set<void*> g_knownLayouts; // seen layout components
        static std::unordered_map<void*, void*> g_layoutByModel; // model -> layout
        static std::unordered_map<void*, uint32_t> g_modelNodeCount; // model -> enumerated node count
        static std::unordered_set<void*> g_enumeratedModels;

        static std::unordered_map<void*, std::vector<void*>> g_nodesByLayout; // layout -> nodes (observed)
        static std::unordered_multimap<void*, void*> g_layoutsByNode; // node -> layout(s)
        static std::unordered_map<void*, std::pair<void*, const void*>> g_anchorByNode; // node -> (parent, port)
        static std::unordered_map<void*, std::pair<void*, const void*>> g_anchorForLayout; // layout -> (parent, port)
        static std::unordered_map<void*, void*> g_injectedNodeByLayout; // layout -> our UiModelText
        static std::unordered_set<void*> g_ourNodes;

        static std::unordered_map<void*, std::string> g_textByNode;
        static std::unordered_map<void*, uint32_t> g_sidByNode;
        static std::unordered_map<void*, bool> g_visByNode;

        static std::atomic<int> g_camoIndex{-1};

        // -----------------------------------------------------------------------------//
        // Utilities
        // -----------------------------------------------------------------------------//
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

        static inline void RememberSid(void* node, uint32_t sid)
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

            std::vector<void*> nodes;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                nodes.reserve(g_injectedNodeByLayout.size());
                for (auto& kv : g_injectedNodeByLayout) nodes.push_back(kv.second);
            }
            for (void* n : nodes) UpdateTextForNode(uix, n);
        }

        // -----------------------------------------------------------------------------//
        // Model selection / enumeration
        // -----------------------------------------------------------------------------//
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

            // 1) Try direct GetModelWrapper(layout,…)
            void* model = nullptr;
            Seh("GetModelWrapper.probe", layout, [&]
            {
                model = GetModelWrapper(layout, nullptr, 0);
                if (model && !GetModelNodeFromIndex(model, 0)) model = nullptr;
            });
            if (model) return model;

            // 2) Fall back to most “populated” known model for this layout
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

        // --- new helpers ---
        static const void* TryGetAnyCommonPort(void* model)
        {
            const void* port = nullptr;

            // First try the vfunc (some models do have a default)
            Seh("GetModelNodeCommon", model, [&]
            {
                port = GetModelNodeCommon(model);
            });
            if (port) return port;

            // Fallback: scan model->commonPorts[] (base at +0x98, count at +0x90)
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

        // Optional: dump all common ports for a model with their SIDs (node+0x6C)
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
                    // 0x6C is where GetModelNodeCommonInternal compared EDX, i.e., the common SID.
                    Seh("ReadCommonSid", node, [&]
                    {
                        sid = *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(node) + 0x6C);
                    });
                    spdlog::info("[PORT]   [{}] node={} sid=#{:08X}", i, node, sid);
                }
            });
        }


        // -----------------------------------------------------------------------------//
        // Anchor resolution — prefers SID’d node, falls back to generic common node
        // -----------------------------------------------------------------------------//
        // Replace the body of TryResolveAnchorForLayout with:
        static bool TryResolveAnchorForLayout(void* layout, std::pair<void*, const void*>& out)
        {
            if (!layout) return false;

            void* model = PickAnchorModelForLayout(layout);
            if (!model)
            {
                spdlog::info("[ROOT] layout={} no model yet; cannot resolve anchor.", layout);
                return false;
            }

            const void* port = TryGetAnyCommonPort(model);
            if (!port)
            {
                spdlog::info("[ROOT] layout={} model={} has no default common port and none enumerated; skip.", layout,
                             model);
                return false;
            }

            out = {layout, port};
            spdlog::info("[ROOT] layout={} anchor via common[]: parent={} port={}", layout, layout, port);
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

        // -----------------------------------------------------------------------------//
        // Injection
        // -----------------------------------------------------------------------------//
        static size_t Inject_AllAnchoredLayouts()
        {
            spdlog::info("0");
            void** ppUix = GetGlobalUixUtility();
            void* uix = ppUix ? *ppUix : nullptr;
            if (!uix)
            {
                spdlog::warn("[ROOT] UIX utility not available; aborting inject.");
                return 0;
            }

            spdlog::info("1");
            // Try to resolve any missing anchors right before injection
            size_t newlyAnchored = ResolveAnchors_AllLayouts();
            if (newlyAnchored) spdlog::info("[ROOT] newly resolved anchors: {}", newlyAnchored);

            spdlog::info("2");
            std::vector<void*> layouts;
            {
                std::lock_guard<std::mutex> _l(g_mx);
                for (auto& L : g_knownLayouts) layouts.push_back(L);
            }

            size_t injected = 0;
            for (void* layout : layouts)
            {
                spdlog::info("3");
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

                spdlog::info("4");
                void* node = NewUiModelText(0, nullptr, nullptr, nullptr);
                if (!node)
                {
                    spdlog::warn("[ROOT] NewUiModelText failed for layout={}", layout);
                    continue;
                }
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    g_ourNodes.insert(node);
                }

                spdlog::info("5");
                UpdateTextForNode(uix, node);
                SetModelNodePriority(uix, node, 240);
                SetModelNodeTextFontSize(uix, node, 28.0f, 0.0f);
                SetModelNodeTextColorRGB(uix, node, 1.0f, 1.0f, 1.0f);

                spdlog::info("6");
                bool ok = Seh("NodeConnectShim", node, [&]
                {
                    NodeConnectShim(node, anchor.first, const_cast<void*>(anchor.second));
                });
                if (!ok)
                {
                    spdlog::warn("[ROOT] NodeConnectShim failed; layout={} node={}", layout, node);
                    continue;
                }

                spdlog::info("7");
                bool vis = IsNodeVisible(uix, node);
                RememberVis(node, vis);

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

        static void DumpInjected()
        {
            void** ppUix = GetGlobalUixUtility();
            void* uix = ppUix ? *ppUix : nullptr;

            spdlog::info("[ROOT] ===== Injection Status ({} layouts) =====", g_injectedNodeByLayout.size());
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
            spdlog::info("[ROOT] =========================================");
        }

        // -----------------------------------------------------------------------------//
        // Hotkeys
        // -----------------------------------------------------------------------------//
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
                spdlog::warn("[HK] F7 -> ROOT inject attempt on all layouts");
                size_t n = Inject_AllAnchoredLayouts();
                spdlog::info("[ROOT] injected {} layout(s).", n);
            }
            if (JustPressed(VK_F8))
            {
                spdlog::info("[HK] F8 -> dump injected status");
                DumpInjected();
            }
            // In PollHotkeys():
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
                spdlog::info(
                    "[HK] F10 -> resolve anchors (IsHaveModelNodeCommon + GetModelNodeCommonInternal/Generic)");
                size_t n = ResolveAnchors_AllLayouts();
                spdlog::info("[ROOT] anchors resolved: {}", n);
            }
        }

        // -----------------------------------------------------------------------------//
        // Hooks (light logging; forward to originals)
        // -----------------------------------------------------------------------------//
        // text hooks
        void __fastcall SetTextForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, const char* rawText,
                                                    bool isLocalized)
        {
            if (rawText && *rawText) RememberText(nodeText, rawText);
            SetTextForModelNodeText(uix, nodeText, textUnit, rawText, isLocalized);
        }

        void __fastcall SetTextUnitsForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, uint32_t unitId)
        {
            RememberSid(nodeText, unitId);
            SetTextUnitsForModelNodeText(uix, nodeText, textUnit, unitId);
        }

        bool __fastcall SetTextUnitsHook(void* nodeText, void* textUnit, uint32_t stringId)
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
        void* __fastcall NodeConnectShimHook(void* node, void* parentComp, void* portNode)
        {
            void* ret = NodeConnectShim(node, parentComp, portNode);

            {
                std::lock_guard<std::mutex> _l(g_mx);
                g_anchorByNode[node] = {parentComp, portNode};
            }
            {
                std::lock_guard<std::mutex> _l(g_mx);
                bool ours = g_ourNodes.count(node) != 0;
                auto rng = g_layoutsByNode.equal_range(node);
                for (auto it = rng.first; it != rng.second; ++it)
                {
                    void* L = it->second;
                    if (!L) continue;
                    if (!ours && g_anchorForLayout.find(L) == g_anchorForLayout.end() && parentComp && portNode)
                    {
                        g_anchorForLayout[L] = {parentComp, portNode};
                        spdlog::info("[ROOT] learned anchor: layout={} parent={} port={} (node={})",
                                     L, parentComp, portNode, node);
                    }
                }
            }
            return ret;
        }

        // model discovery
        void* __fastcall GetModelWrapperHook(void* layout, void* outModel, uint32_t outRoot)
        {
            void* ret = GetModelWrapper(layout, outModel, outRoot);

            if (layout)
            {
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    g_knownLayouts.insert(layout);
                }

                void* model = nullptr;
                Seh("GMw.ret.probe", ret, [&] { if (ret && GetModelNodeFromIndex(ret, 0)) model = ret; });
                if (!model && outModel)
                {
                    Seh("GMw.outModel.read", outModel, [&]
                    {
                        void* cand = *(void**)outModel;
                        if (cand && GetModelNodeFromIndex(cand, 0)) model = cand;
                    });
                }
                if (model)
                {
                    {
                        std::lock_guard<std::mutex> _l(g_mx);
                        g_layoutByModel[model] = layout;
                    }
                    EnumerateModelNodes(model, layout, 4096);
                }
            }
            return ret;
        }

        void* __fastcall GetModelNodeFromIndexHook(const void* model, int index)
        {
            return GetModelNodeFromIndex(model, index);
        }

        void* __fastcall GetModelNodeCommonHook(void* selfModel)
        {
            // Light trace (comment out if chatty)
            // spdlog::trace("GetModelNodeCommon: model={}", selfModel);
            return GetModelNodeCommon(selfModel);
        }

        void* __fastcall GetModelNodeCommonInternalHook(void* selfModel, uint32_t sid)
        {
            // spdlog::trace("GetModelNodeCommonInternal: model={} sid=0x{:08X}", selfModel, sid);
            return GetModelNodeCommonInternal(selfModel, sid);
        }

        bool __fastcall IsHaveModelNodeCommonHook(void* selfUixUtility, const void* model, uint64_t stringId)
        {
            bool have = IsHaveModelNodeCommon(selfUixUtility, model, stringId);
            // spdlog::trace("IsHaveModelNodeCommon: model={} sid=0x{:08X} have={}", model, (uint32_t)stringId, have ? "T":"F");
            return have;
        }

        void __fastcall OnLayoutComponentDestroyHook(void* self)
        {
            OnLayoutComponentDestroy(self);
        }

        void* __fastcall NewUiModelTextHook(uint32_t sceneStrCode32, void* creationCtx, void* opt0, void* opt1)
        {
            spdlog::info("NewUiModelTextHook: sceneStrCode32={} creationCtx={} opt0={} opt1={}", sceneStrCode32, creationCtx, opt0, opt1);
            return NewUiModelText(sceneStrCode32, creationCtx, opt0, opt1);
        }

        const void* __fastcall LoadCreationContextHook(const void* serializedBlob, void* outCtx)
        {
            spdlog::info("LoadCreationContextHook: serializedBlob={} outCtx={}", serializedBlob, outCtx);
            return LoadCreationContext(serializedBlob, outCtx);
        }
        void __fastcall UpdateWindowGraphHook(void* selfWindow)
        {
            spdlog::info("UpdateWindowGraphHook: selfWindow={}", selfWindow);
            UpdateWindowGraph(selfWindow);
        }
        void __fastcall AddChildWindowHook(void* selfWindow, void* childWindow)
        {
            spdlog::info("AddChildWindowHook: selfWindow={} childWindow={}", selfWindow, childWindow);
            AddChildWindow(selfWindow, childWindow);
        }
        void* __fastcall CreateNewWindowHook(void* cls /*WindowFunction* or service*/, void* nameStr, uint32_t flagsA, uint32_t flagsB)
        {
            spdlog::info("LoadCreationContextHook: cls={} nameStr={} flagsA={} flagsB={}", cls, nameStr,flagsA ,flagsB);
            return CreateNewWindow(cls, nameStr,flagsA ,flagsB);
        }
        void* __fastcall GetWindowManagerHook()
        {
            // spdlog::info("GetWindowManagerHook");
            return GetWindowManager();
        }

        // frame/update
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);
            MaybeRefreshInjectedText();
            PollHotkeys();
        }

        // -----------------------------------------------------------------------------//
        // Install
        // -----------------------------------------------------------------------------//
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
            CREATE_HOOK(LoadCreationContext)

            CREATE_HOOK(UpdatePhaseUi)
            
            CREATE_HOOK(UpdateWindowGraph)
            CREATE_HOOK(AddChildWindow)
            CREATE_HOOK(CreateNewWindow)
            CREATE_HOOK(GetWindowManager)

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
            ENABLEHOOK(LoadCreationContext)

            ENABLEHOOK(UpdatePhaseUi)
            
            ENABLEHOOK(UpdateWindowGraph)
            ENABLEHOOK(AddChildWindow)
            ENABLEHOOK(CreateNewWindow)
            ENABLEHOOK(GetWindowManager)

            spdlog::info(
                "[UI-HOOK] Hooks installed (ROOT via Model::GetModelNodeCommonInternal/IsHaveModelNodeCommon).");
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
