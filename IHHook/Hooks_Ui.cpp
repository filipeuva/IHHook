#include "Hooks_Ui.h"
#include "hooks/mgsvtpp_func_typedefs.h"
#include "MinHook.h"
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"

#include <windows.h>
#include <atomic>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <climits>

#include <vector>
#include <mutex>
#include <algorithm>
#include <shared_mutex>

#include <string>

namespace IHHook
{
    namespace Hooks_Ui
    {
        // ---------- Engine opaque types ----------
        using UiLayout = void; // fox::ui::Layout
        using UiModel = void; // fox::ui::Model
        using UiModelNode = void; // fox::ui::ModelNode
        using UiModelText = void; // fox::ui::ModelNodeText
        using UiWindow = void; // fox::ui::Window
        using WindowFuncIF = void; // some WindowFunction* / factory iface

        // ---------- Switches ----------
        static constexpr bool kEnableFactoryHooks = false; // hard OFF by default

        // ---------------------------------------------------------------------
        // TARGETS / STATE
        // ---------------------------------------------------------------------
        static std::unordered_set<uint64_t> g_targetSig64s = {
            0x6E6A53858C7D348A, // Main Menu
        };

        struct HandleLink
        {
            void* parentWindow{};
            void* slotObj{}; // Window slot entry object
            void* parentComp{}; // LayoutComponent*
            const void* portNode{}; // ModelNode const*
            void* handle{}; // windowHandle
            void* wf{}; // WindowFunction* (equals handle on this build)
            UiLayout* parentLayout{}; // optional
        };

        using FnFactory = void* (__fastcall*)(void* handle);

        struct FactoryTLS
        {
            void* slotObj{};
            void* parentComp{};
            const void* portNode{};
            void* handle{};
            bool active{};
            uint32_t depth{};
        };

        static thread_local FactoryTLS g_ftls;

        // vtable pointer -> original factory fn
        static std::unordered_map<void**, FnFactory> g_origFactoryByVt;
        static std::unordered_set<void**> g_hookedFactoryVt;
        static std::shared_mutex g_factoryMx;

        // childComp -> linkage (for debugging/correlation)
        static std::unordered_map<void*, HandleLink> g_linkByChildComp;

        static std::unordered_map<UiLayout*, uint64_t> g_sigByLayout;
        static std::unordered_map<UiLayout*, uint64_t> g_currentSigByLayout;
        static std::unordered_map<UiLayout*, std::unordered_set<uintptr_t>> g_vtblsByLayout;
        static std::unordered_map<void*, void*> g_wfByHandle;
        static std::unordered_map<void*, UiLayout*> g_layoutByWf;

        // Text creation ctx harvested at runtime
        static uint32_t g_lastTextSceneStr = 0;
        static void* g_lastTextCreationCtx = nullptr;

        struct Anchor
        {
            UiLayout* layout{};
            void* slotObj{};
            void* parentComp{};
            const void* portNode{};
            void* windowHandle{};
            void* windowFunction{};
            uint64_t windowSig{};
        };

        struct PortKey
        {
            void* parentComp{};
            const void* portNode{};
            bool operator==(const PortKey& o) const { return parentComp == o.parentComp && portNode == o.portNode; }
        };

        struct PortKeyHash
        {
            size_t operator()(const PortKey& k) const
            {
                return std::hash<uintptr_t>()(reinterpret_cast<uintptr_t>(k.parentComp)) ^
                    (std::hash<uintptr_t>()(reinterpret_cast<uintptr_t>(k.portNode)) << 1);
            }
        };

        static std::unordered_map<uint64_t, Anchor> g_anchorByWindowSig;
        static std::unordered_map<PortKey, Anchor, PortKeyHash> g_anchorByPort;
        static std::unordered_map<PortKey, std::string, PortKeyHash> g_pendingInjectByPort;
        static std::unordered_map<void*, HandleLink> g_linkByHandle;

        struct PendingTextRec
        {
            // target
            void* parentWindow{};
            void* parentComp{};
            const void* portNode{};

            // payload
            void* nodeText{};
            std::string utf8;
            float wantW{512.0f};
            float wantH{64.0f};

            // lifecycle
            bool materialized{false}; // engine created a LayoutComponent for nodeText
            void* childComp{}; // resolved LayoutComponent*
        };

        static std::unordered_map<void*, PendingTextRec> g_pendingByNode; // key=nodeText
        static std::unordered_map<PortKey, std::vector<void*>, PortKeyHash> g_nodesByPort; // port -> [nodeText]

        // --- Investigation state ---
        static std::unordered_set<uintptr_t> g_layoutCompVts; // vtables observed as childComp in CLC
        static std::unordered_set<void*> g_seenCLC_callers; // return addresses calling CLC
        static std::unordered_set<uintptr_t> g_dumpedChildVtOnce; // one-time hex dump per child vt
        static std::unordered_map<uintptr_t, size_t> g_childVtToNodeOff; // child vt -> nodeText offset, if found

        // Prove GetLayoutComponent works
        static bool g_lightLogs = true;
#define LOGI(...) do{ if(!g_lightLogs) spdlog::info(__VA_ARGS__); else spdlog::debug(__VA_ARGS__);}while(0)
#define LOGW(...) spdlog::warn(__VA_ARGS__)
#define LOGE(...) spdlog::error(__VA_ARGS__)

        // === proof + attach discovery state ===
        static std::unordered_map<uintptr_t, bool> g_vtProofDone;
        static std::unordered_map<uintptr_t, bool> g_vtProofPass;
        static std::unordered_map<uintptr_t, size_t> g_vtProofNodeOff;
        static std::unordered_map<uintptr_t, void*> g_vtProofNodePtr;
        static std::unordered_map<uintptr_t, void*> g_vtProofCompPtr;

        static std::unordered_map<uintptr_t, std::unordered_map<void*, uint32_t>> g_seenChildPerVT;
        // VT -> childComp -> seen count
        static std::unordered_map<uintptr_t, std::unordered_map<void*, uint32_t>> g_attachCandidates;
        // VT -> callerAddr -> hits

        // ---------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------
        static inline uint64_t ADR(const void* p) { return reinterpret_cast<uint64_t>(p); }
        static inline uint64_t ADRF(void* p) { return reinterpret_cast<uint64_t>(p); }

        static void DumpBacktrace(const char* tag, int skip = 1, int max = 16)
        {
            void* frames[64]{};
            USHORT n = RtlCaptureStackBackTrace(static_cast<DWORD>(skip + 1),
                                                static_cast<DWORD>(max),
                                                frames, nullptr);
            for (USHORT i = 0; i < n; ++i)
            {
                spdlog::debug("[BT:{}] #{} 0x{:016X}", tag, i, reinterpret_cast<uint64_t>(frames[i]));
            }
        }

        static inline uintptr_t VT(void* p) { return p ? *reinterpret_cast<uintptr_t*>(p) : 0; }
        static inline uintptr_t VTc(const void* p) { return p ? *reinterpret_cast<const uintptr_t*>(p) : 0; }

        static uint64_t FNV1a64(const void* data, size_t len)
        {
            const uint8_t* b = static_cast<const uint8_t*>(data);
            uint64_t h = 0xcbf29ce484222325ULL;
            for (size_t i = 0; i < len; ++i)
            {
                h ^= b[i];
                h *= 0x100000001b3ULL;
            }
            return h;
        }

        static uint64_t FNV1a64_3(uintptr_t a, uintptr_t b, uintptr_t c)
        {
            uint64_t h = 0xcbf29ce484222325ULL;
            auto mix = [&](uintptr_t x)
            {
                for (int i = 0; i < 8 * sizeof(void*); i += 8)
                {
                    h ^= (x >> i) & 0xFF;
                    h *= 0x100000001b3ULL;
                }
            };
            mix(a);
            mix(b);
            mix(c);
            return h;
        }

        static uint64_t HashSortedVTables(const std::unordered_set<uintptr_t>& vtset)
        {
            std::vector<uintptr_t> v(vtset.begin(), vtset.end());
            std::sort(v.begin(), v.end());
            return FNV1a64(v.data(), v.size() * sizeof(uintptr_t));
        }

        static void RecomputeLayoutSig(UiLayout* layout)
        {
            auto it = g_vtblsByLayout.find(layout);
            if (it == g_vtblsByLayout.end()) return;
            uint64_t sig = HashSortedVTables(it->second);
            g_sigByLayout[layout] = sig;
            g_currentSigByLayout[layout] = sig;
        }

        static uint64_t ComputeWindowSig_direct(void* parentComp, const void* portNode, void* windowHandle)
        {
            return FNV1a64_3(VT(parentComp), VTc(portNode), reinterpret_cast<uintptr_t>(windowHandle));
        }

        static void DumpAnchors()
        {
            spdlog::info("===== Window-route anchors =====");
            for (const auto& kv : g_anchorByWindowSig)
            {
                const Anchor& a = kv.second;
                spdlog::info("[ANCHOR] winSig=0x{:016X} handle={} parentComp={} portNode={} slotObj={} wf={}",
                             a.windowSig, a.windowHandle, a.parentComp, a.portNode, a.slotObj, a.windowFunction);
            }
        }

        static const char* yn(bool v) { return v ? "yes" : "no"; }

        static bool IsReadablePtr(const void* p)
        {
            if (!p) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT) return false;
            if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
            const DWORD ok = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
            return (mbi.Protect & ok) != 0;
        }

        static void DebugHexDumpOnce(uintptr_t vtKey, const void* base, size_t bytes = 0x100)
        {
            if (!base) return;
            if (!g_dumpedChildVtOnce.insert(vtKey).second) return;
            if (!IsReadablePtr(base)) return;

            const uint8_t* p = static_cast<const uint8_t*>(base);
            std::string line;
            line.reserve(128);
            for (size_t i = 0; i < bytes; i += 16)
            {
                if (!IsReadablePtr(p + i)) break;
                line.clear();
                line += fmt::format("{:p} : ", static_cast<const void*>(p + i));
                for (size_t j = 0; j < 16 && i + j < bytes; ++j)
                {
                    line += fmt::format("{:02X} ", p[i + j]);
                }
                spdlog::debug("[CLC/HEXDUMP] {}", line);
            }
        }

        // Scan first N bytes of a candidate component for an embedded ModelNodeText* by tag 0x03 at +0x72
        static void* ProbeNodeTextFromChildComp(void* childComp, size_t* outOff /*nullable*/, size_t scanBytes = 0x80)
        {
            if (!childComp) return nullptr;
            uint8_t* base = static_cast<uint8_t*>(childComp);
            for (size_t off = 0; off <= scanBytes; off += 8)
            {
                void* cand = *reinterpret_cast<void**>(base + off);
                if (!IsReadablePtr(cand)) continue;
                uint8_t* tagPtr = static_cast<uint8_t*>(cand) + 0x72;
                if (!IsReadablePtr(tagPtr)) continue;
                if (*tagPtr == 0x03)
                {
                    if (outOff) *outOff = off;
                    return cand;
                }
            }
            return nullptr;
        }

        // ---------------------------------------------------------------------
        // Minimal text writer (no CreateBoxText)
        // ---------------------------------------------------------------------
        static void SetNodeTextRaw(void* nodeText, const char* utf8)
        {
            if (!nodeText || !utf8) return;

            void* tu = GetTextUnits(0);
            if (!tu)
            {
                spdlog::warn("[TEXT] GetTextUnits(0)=null");
                return;
            }

            SetTextUnit(tu,
                        const_cast<char*>(utf8),
                        /*flags*/0, /*p3*/0, /*p4*/0,
                        /*size*/24.0f,
                        /*tracking*/0.0f,
                        /*p7*/0, /*p8*/0);

            (void)SetTextUnits(nodeText, tu, /*stringId*/0);
            SetModelNodeTextDisplayWidth(nodeText, 512.0f);
            SetModelNodeTextDisplayHeight(nodeText, 64.0f);
        }

        // ---------------------------------------------------------------------
        // Proof helpers
        // ---------------------------------------------------------------------
        static void Prove_NodeTextComponentIdentity(void* childComp)
        {
            if (!childComp) return;
            const uintptr_t vtc = VT(childComp);
            if (g_vtProofDone.count(vtc)) return;

            auto itOff = g_childVtToNodeOff.find(vtc);
            if (itOff == g_childVtToNodeOff.end()) return;

            size_t off = itOff->second;
            void* nodeT = *reinterpret_cast<void**>(static_cast<uint8_t*>(childComp) + off);
            if (!IsReadablePtr(nodeT)) return;

            void* compFromGetter = GetLayoutComponent(nodeT);

            const bool ok = (compFromGetter == childComp);
            g_vtProofDone[vtc] = true;
            g_vtProofPass[vtc] = ok;
            g_vtProofNodeOff[vtc] = off;
            g_vtProofNodePtr[vtc] = nodeT;
            g_vtProofCompPtr[vtc] = childComp;

            if (ok)
                spdlog::info("[PROOF] VT=0x{:016X} nodeText={} +0x{:X} => GetLayoutComponent(node)==childComp",
                             (uint64_t)vtc, nodeT, (unsigned)off);
            else
                LOGW("[PROOF] VT=0x{:016X} nodeText={} +0x{:X} => GetLayoutComponent(node)={} != childComp={}",
                 (uint64_t)vtc, nodeT, (unsigned)off, compFromGetter, childComp);
        }

        static void CaptureAttachCaller(void* childComp)
        {
            if (!childComp) return;
            const uintptr_t vtc = VT(childComp);

            void* frames[8]{};
            USHORT n = RtlCaptureStackBackTrace(1, 8, frames, nullptr); // skip current hook frame
            if (!n) return;

            void* caller = frames[0];
            if (!caller) return;

            auto& freqMap = g_attachCandidates[vtc];
            ++freqMap[caller];

            auto& seenMap = g_seenChildPerVT[vtc];
            uint32_t& seen = seenMap[childComp];
            if (seen++ == 0)
                LOGI("[ATTACH?] VT=0x{:016X} childComp={} caller=0x{:016X}", (uint64_t)vtc, childComp,
                 (uint64_t)caller);
        }

        static void DumpAttachCandidates()
        {
            spdlog::info("===== Attach-caller candidates by Component VT =====");
            for (auto& vtEntry : g_attachCandidates)
            {
                const uintptr_t vtc = vtEntry.first;
                spdlog::info("VT 0x{:016X}:", (uint64_t)vtc);

                std::vector<std::pair<void*, uint32_t>> v(vtEntry.second.begin(), vtEntry.second.end());
                std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });

                int cap = 6;
                for (auto& kv : v)
                {
                    spdlog::info("  caller 0x{:016X} hits {}", (uint64_t)kv.first, kv.second);
                    if (--cap <= 0) break;
                }

                auto itP = g_vtProofPass.find(vtc);
                if (itP != g_vtProofPass.end())
                {
                    spdlog::info("  proof: {}", itP->second ? "GetLayoutComponent(node)==childComp" : "MISMATCH");
                    if (itP->second)
                        spdlog::info("  node@+0x{:X} = {}", (unsigned)g_vtProofNodeOff[vtc], g_vtProofNodePtr[vtc]);
                }
            }
        }

        static void DumpProofSummary()
        {
            spdlog::info("===== NodeText ↔ LayoutComponent identity proofs =====");
            for (auto& kv : g_vtProofDone)
            {
                const uintptr_t vt = kv.first;
                bool pass = g_vtProofPass[vt];
                spdlog::info("VT 0x{:016X} -> {}", (uint64_t)vt, pass ? "OK" : "FAIL");
                if (pass)
                {
                    spdlog::info("  node@+0x{:X} {}  comp {}", (unsigned)g_vtProofNodeOff[vt],
                                 g_vtProofNodePtr[vt], g_vtProofCompPtr[vt]);
                }
            }
        }

        // ---------------------------------------------------------------------
        // Injection (now active; no NodeConnectShim; no CreateBoxText)
        // ---------------------------------------------------------------------

        // Create UiModelText now, but DON'T attach or set units. Defer until component exists.
        static void* CreatePendingForLink(const HandleLink& L, const char* utf8)
        {
            if (!L.parentWindow || !L.parentComp || !L.portNode)
            {
                spdlog::warn("[PENDING] missing linkage (parentComp={}, portNode={}, parentWindow={})",
                             L.parentComp, L.portNode, L.parentWindow);
                return nullptr;
            }
            if (!g_lastTextCreationCtx)
            {
                spdlog::warn("[PENDING] no creationCtx yet; will requeue on port");
                g_pendingInjectByPort[PortKey{L.parentComp, L.portNode}] = utf8 ? utf8 : "Hello World";
                return nullptr;
            }

            spdlog::info("[PENDING] NewUiModelText");
            void* nodeText = NewUiModelText(g_lastTextSceneStr, g_lastTextCreationCtx, nullptr, nullptr);
            if (!nodeText)
            {
                spdlog::warn("[PENDING] NewUiModelText failed");
                return nullptr;
            }

            PendingTextRec rec{};
            rec.parentWindow = L.parentWindow;
            rec.parentComp   = L.parentComp;
            rec.portNode     = L.portNode;
            rec.nodeText     = nodeText;
            rec.utf8         = (utf8 && *utf8) ? utf8 : "Hello World";

            g_nodesByPort[PortKey{L.parentComp, L.portNode}].push_back(nodeText);
            g_pendingByNode[nodeText] = std::move(rec);

            spdlog::info("[PENDING] nodeText={} queued for port parentComp={} portNode={}", nodeText, L.parentComp, L.portNode);
            return nodeText;
        }

        // Called on every UI phase to complete any pending whose component exists.
        static void ProcessPendingsTick()
        {
            if (g_pendingByNode.empty()) return;

            for (auto it = g_pendingByNode.begin(); it != g_pendingByNode.end();)
            {
                PendingTextRec& p = it->second;
                
                // 1) Ensure the engine actually creates a LayoutComponent for this node.
                if (!p.materialized || !p.childComp)
                {
                    // First, try polling (cheap).
                    spdlog::info("[PROCESS PENDING] GetLayoutComponent");
                    void* comp = GetLayoutComponent(p.nodeText);
                    if (!comp)
                    {
                        // If still null, force materialization through the proper FOX path.
                        // This respects the engine (it builds the component for our node under the container),
                        // and CLC will observe the subsequent ConnectLayoutComponent we do below.
                        void* tu = GetTextUnits(0);
                        if (tu)
                        {
                            // Prime text units so the node is valid for finalize
                            spdlog::info("[PROCESS PENDING] SetTextUnit");
                            SetTextUnit(tu,
                                        const_cast<char*>((p.utf8.empty() ? "" : p.utf8.c_str())),
                                        /*flags*/0, /*p3*/0, /*p4*/0,
                                        /*size*/24.0f, /*tracking*/0.0f, /*p7*/0, /*p8*/0);
                        } else
                        {
                            spdlog::info("[PROCESS PENDING] GetTextUnits(0)=null");
                        }

                        spdlog::info("[PROCESS PENDING] AttachTextAndFinalize");
                        int ok = AttachTextAndFinalize(p.parentWindow, p.parentComp, p.nodeText, tu);
                        if (!ok)
                        {
                            // Could be a transient timing window; keep the pending alive and try again next tick.
                            ++it;
                            continue;
                        }

                        // Re-probe component after finalize
                        comp = GetLayoutComponent(p.nodeText);
                    }

                    if (!comp)
                    {
                        // Still nothing; keep waiting (rare).
                        ++it;
                        continue;
                    }

                    p.materialized = true;
                    p.childComp = comp;
                    spdlog::debug("[PENDING→MATERIALIZED] nodeText={} childComp={} parentComp={}",
                                  p.nodeText, p.childComp, p.parentComp);
                }

                // 2) Bind the freshly-built component to the requested port.
                ConnectLayoutComponent(p.childComp, p.parentComp, const_cast<void*>(p.portNode));

                // 3) Now content/metrics/visibility.
                if (!p.utf8.empty())
                {
                    void* tu = GetTextUnits(0);
                    if (tu)
                    {
                        SetTextUnit(tu,
                                    const_cast<char*>(p.utf8.c_str()),
                                    /*flags*/0, /*p3*/0, /*p4*/0,
                                    /*size*/24.0f, /*tracking*/0.0f, /*p7*/0, /*p8*/0);
                        (void)SetTextUnits(p.nodeText, tu, /*stringId*/0);
                    }
                }

                SetModelNodeTextDisplayWidth(p.nodeText, p.wantW);
                SetModelNodeTextDisplayHeight(p.nodeText, p.wantH);
                SetNodeVisibility(p.nodeText, true);

                // 4) Render this frame.
                UpdateWindowGraph(p.parentWindow);

                spdlog::info("[INJECT/DEFERRED] OK nodeText={} childComp={} parentComp={} portNode={}",
                             p.nodeText, p.childComp, p.parentComp, p.portNode);

                // 5) Cleanup bookkeeping.
                auto vecIt = g_nodesByPort.find(PortKey{p.parentComp, p.portNode});
                if (vecIt != g_nodesByPort.end())
                {
                    auto& v = vecIt->second;
                    v.erase(std::remove(v.begin(), v.end(), p.nodeText), v.end());
                    if (v.empty()) g_nodesByPort.erase(vecIt);
                }
                it = g_pendingByNode.erase(it);
            }
        }

        // --- REPLACE DoInjectText with a deferred creator that DOES NOT attach/finalize now ---
        static void* DoInjectText(const HandleLink& L, const char* utf8)
        {
            return CreatePendingForLink(L, utf8);
        }

        // --- EDIT BeginInject_ByWindowSig to NOT force ConnectWindowToParent; just queue by port or create pending if link known ---
        static void BeginInject_ByWindowSig(uint64_t winSig, const char* text)
        {
            auto it = g_anchorByWindowSig.find(winSig);
            if (it == g_anchorByWindowSig.end())
            {
                spdlog::error("[INJECT] No anchor for 0x{:016X}", winSig);
                return;
            }
            const Anchor& a = it->second;

            auto itL = g_linkByHandle.find(a.windowHandle);
            if (itL != g_linkByHandle.end())
            {
                const HandleLink& L = itL->second;
                CreatePendingForLink(L, (text && *text) ? text : "Hello World");
                return;
            }

            // No link yet: record intent for that port; ConnectChildWindowToNodeHook will convert to a pending when window wires up.
            g_pendingInjectByPort[PortKey{a.parentComp, a.portNode}] = (text && *text) ? text : "Hello World";
            spdlog::info("[INJECT] queued by port: parentComp={} portNode={}", a.parentComp, a.portNode);
        }

        // Detour + optional factory vt[22] path (kept behind a gate)
        // ---------------------------------------------------------------------
        static void* __fastcall WindowChildFactoryDetour(void* handle)
        {
            void** vt = handle ? *reinterpret_cast<void***>(handle) : nullptr;
            FnFactory orig = nullptr;
            {
                std::shared_lock lk(g_factoryMx);
                auto it = g_origFactoryByVt.find(vt);
                if (it != g_origFactoryByVt.end()) orig = it->second;
            }

            void* child = orig ? orig(handle) : nullptr;

            DumpBacktrace("FACTORY", 0, 16);

            if (child)
            {
                uintptr_t vtc = VT(child);
                IHHook::Hooks_Ui::g_layoutCompVts.insert(vtc);
                if (IHHook::Hooks_Ui::g_childVtToNodeOff.find(vtc) == IHHook::Hooks_Ui::g_childVtToNodeOff.end())
                {
                    size_t off = SIZE_MAX;
                    void* nodeT = IHHook::Hooks_Ui::ProbeNodeTextFromChildComp(child, &off, 0x80);
                    if (nodeT)
                    {
                        IHHook::Hooks_Ui::g_childVtToNodeOff[vtc] = off;
                        spdlog::info("[FACTORY/MAP] vt(child)=0x{:016X} nodeText={} off=+0x{:X}",
                                     static_cast<uint64_t>(vtc), nodeT, (unsigned)off);
                    }
                }
            }

            if (g_ftls.active)
            {
                spdlog::info("[FACTORY] handle={} vt=0x{:016X} -> childComp={} slotObj={} parentComp={} portNode={}",
                             handle, reinterpret_cast<uint64_t>(*reinterpret_cast<void***>(handle)),
                             child, g_ftls.slotObj, g_ftls.parentComp, g_ftls.portNode);
            }
            else
            {
                spdlog::debug("[FACTORY] handle={} vt=0x{:016X} -> childComp={} (no TLS)",
                              handle, reinterpret_cast<uint64_t>(*reinterpret_cast<void***>(handle)), child);
            }

            return child;
        }

        static void HookFactorySlotForHandle(void* handle)
        {
            if (!handle) return;
            void*** pvt = reinterpret_cast<void***>(handle);
            if (!IsReadablePtr(pvt) || !IsReadablePtr(*pvt)) return;

            void** vt = *pvt;
            {
                std::shared_lock lk(g_factoryMx);
                if (g_hookedFactoryVt.count(vt)) return;
            }

            void* target = vt[22]; // slot index 22 == 0xB0
            if (!target) return;

            DWORD oldProt{};
            if (!VirtualProtect(&vt[22], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt))
            {
                spdlog::warn("[FACTORY/HOOK] VirtualProtect failed vt={} slot22", ADR(vt));
                return;
            }

            {
                std::unique_lock lk(g_factoryMx);
                if (!g_hookedFactoryVt.insert(vt).second)
                {
                    VirtualProtect(&vt[22], sizeof(void*), oldProt, &oldProt);
                    return;
                }
                g_origFactoryByVt[vt] = reinterpret_cast<FnFactory>(target);
                vt[22] = reinterpret_cast<void*>(&WindowChildFactoryDetour);
            }

            VirtualProtect(&vt[22], sizeof(void*), oldProt, &oldProt);

            spdlog::info("[FACTORY/HOOK] vt=0x{:016X} slot[22] 0x{:016X} -> 0x{:016X}",
                         ADR(vt), ADR(target),
                         static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&WindowChildFactoryDetour)));
        }

        static inline void MaybeHookFactorySlotForHandle(void* handle)
        {
            if constexpr (kEnableFactoryHooks) HookFactorySlotForHandle(handle);
        }

        // ---- TLS helpers for window path ----
        struct FTLSGuard
        {
            bool armed{false};

            FTLSGuard(void* slotObj, const void* parentComp, const void* portNode, void* handle)
            {
                g_ftls.slotObj = slotObj;
                g_ftls.parentComp = const_cast<void*>(parentComp);
                g_ftls.portNode = portNode;
                g_ftls.handle = handle;
                g_ftls.active = true;
                g_ftls.depth++;
                armed = true;
            }

            ~FTLSGuard()
            {
                if (!armed) return;
                if (g_ftls.depth) g_ftls.depth--;
                if (g_ftls.depth == 0) g_ftls = FactoryTLS{};
            }
        };

        // ---------------------------------------------------------------------
        // Hooks
        // ---------------------------------------------------------------------

        // text hooks
        void __fastcall SetTextForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, const char* rawText,
                                                    bool isLocalized)
        {
            SetTextForModelNodeText(uix, nodeText, textUnit, rawText, isLocalized);
        }

        void __fastcall SetTextUnitsForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, uint64_t stringId)
        {
            SetTextUnitsForModelNodeText(uix, nodeText, textUnit, stringId);
        }

        bool __fastcall SetTextUnitsHook(void* nodeText, void* textUnit, uint64_t stringId)
        {
            bool textUnitSet = SetTextUnits(nodeText, textUnit, stringId);
            spdlog::info("[SET TU] success={} nodeText={} textUnit={} stringId={}", textUnit, nodeText, textUnit, stringId);
            
            return textUnitSet;
        }

        // visibility hooks
        void __fastcall SetNodeVisibilityWrapperHook(void* anyMgr, void* node, bool visible)
        {
            SetNodeVisibilityWrapper(anyMgr, node, visible);
        }

        void __fastcall SetNodeVisibilityHook(void* node, bool visible)
        {
            SetNodeVisibility(node, visible);
        }

        bool __fastcall IsNodeVisibleHook(void* anyMgr, void* node)
        {
            return IsNodeVisible(anyMgr, node);
        }

        void* __fastcall NodeConnectShimHook(void* owner, void* parentComp, void* portPtr, void* childArg)
        {
            uintptr_t vtChild = VT(childArg);
            bool looksComp = (g_layoutCompVts.find(vtChild) != g_layoutCompVts.end());
            spdlog::debug("[NCS] owner={} parentComp={} portNode={} childArg={} vt(child)=0x{:016X} comp={}",
                          owner, parentComp, portPtr, childArg, (uint64_t)vtChild, yn(looksComp));
            return NodeConnectShim(owner, parentComp, portPtr, childArg);
        }

        // Model discovery
        void* __fastcall GetModelWrapperHook(void* layout, void** outModel, uint32_t wantRoot)
        {
            return GetModelWrapper(layout, outModel, wantRoot);
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
            OnLayoutComponentDestroy(self);
        }

        // Creation ctx harvest
        void* __fastcall NewUiModelTextHook(uint32_t sceneStr, void* creationCtx, void* a2, void* a3)
        {
            g_lastTextSceneStr = sceneStr;
            g_lastTextCreationCtx = creationCtx;
            return NewUiModelText(sceneStr, creationCtx, a2, a3);
        }

        // window plumbing hooks
        void __fastcall UpdateWindowGraphHook(void* selfWindow)
        {
            UpdateWindowGraph(selfWindow);
        }

        void __fastcall AddChildWindowHook(void* selfWindow, void* childWindow)
        {
            AddChildWindow(selfWindow, childWindow);
        }

        void* __fastcall CreateNewWindowHook(void* cls /*WindowFunction*/, const void* nameStr, uint32_t flagsA,
                                             uint32_t flagsB)
        {
            return CreateNewWindow(cls, nameStr, flagsA, flagsB);
        }

        void* __fastcall GetWindowManagerHook()
        {
            return GetWindowManager();
        }

        void* __fastcall GetWindowLayoutHook(void* windowFunction, uint64_t layoutId)
        {
            void* L = GetWindowLayout(windowFunction, layoutId);
            if (L)
            {
                g_layoutByWf[windowFunction] = (UiLayout*)L;
                RecomputeLayoutSig((UiLayout*)L);
            }
            return L;
        }

        void* __fastcall FindWindowFactoryHook(void* collector, int hash)
        {
            return FindWindowFactory(collector, hash);
        }

        void __fastcall RegisterWindowFactoryHook(void* collector, void* factory)
        {
            RegisterWindowFactory(collector, factory);
        }

        void* __fastcall GetWindowHandleHook(void* mgr, void* windowFunction)
        {
            auto h = GetWindowHandle(mgr, windowFunction);
            if (h) g_wfByHandle[h] = windowFunction;
            return h;
        }

        void __fastcall SetLayoutInfoHook(void* windowHandle, const void* layoutInfo)
        {
            SetLayoutInfo(windowHandle, layoutInfo);
        }

        void* __fastcall GetTextUnitsHook(int index)
        {
            void* tu = GetTextUnits(index); // original
            spdlog::info("[GET TU] index={} -> {}", index, tu);
            return tu;
        }

        void* __fastcall GetTextUnitsInternalHook(void* fontMgr, int index)
        {
            void* tu = GetTextUnitsInternal(fontMgr, index); // original
            spdlog::info("[GET TUI] fontMgr={} index={} -> {}", fontMgr, index, tu);
            return tu;
        }

        void __fastcall SetTextUnitHook(void* selfTextUnit, char* text, uint32_t flags, uint16_t p3, uint16_t p4,
                                        float size, float tracking, uint32_t p7, uint32_t p8)
        {
            SetTextUnit(selfTextUnit, text, flags, p3, p4, size, tracking, p7, p8);
        }

        void __fastcall DeleteTextUnitHook(void* uixImpl, void* textUnit)
        {
            DeleteTextUnit(uixImpl, textUnit);
        }

        int __fastcall CreateBoxTextHook(void* modelNodeText, void* textUnit, uint32_t unitId,
                                         char* text, bool a, bool b)
        {
            return CreateBoxText(modelNodeText, textUnit, unitId, text, a, b);
        }

        void __fastcall GraphUpdateHook(void* selfGraph)
        {
            spdlog::info("[GRAPH UPDATE] selfGraph={}", selfGraph);

            GraphUpdate(selfGraph);
        }

        void* __fastcall GetUixLayoutHook(void* manager, const void* windowIface, uint64_t layoutId)
        {
            return GetUixLayout(manager, windowIface, layoutId);
        }
        
        void* __fastcall GetGlobalUixUtilityHook()
        {
            auto uix = GetGlobalUixUtility();
            // spdlog::debug("[GLOBAL UIX] Uix={}", uix);
            return uix;
        }

        // Window / layout connects (FIELD route)
        void __fastcall ConnectLayoutComponentHook(void* childComp, void* parentComp, void* portPtr)
        {
            const uintptr_t vtc = VT(childComp);

            if (IHHook::Hooks_Ui::g_childVtToNodeOff.find(vtc) == IHHook::Hooks_Ui::g_childVtToNodeOff.end())
            {
                size_t off = SIZE_MAX;
                void* nodeT = IHHook::Hooks_Ui::ProbeNodeTextFromChildComp(childComp, &off, 0x80);
                if (nodeT)
                {
                    IHHook::Hooks_Ui::g_childVtToNodeOff[vtc] = off;
                    LOGI("[MAP] childVT=0x{:016X} nodeText={} off=+0x{:X}", (uint64_t)vtc, nodeT, (unsigned)off);
                }
            }

            // If this child has one of our nodeText pointers, mark it materialized and capture comp.
            auto itOff = g_childVtToNodeOff.find(vtc);
            if (itOff != g_childVtToNodeOff.end())
            {
                size_t off = itOff->second;
                if (IsReadablePtr(childComp))
                {
                    void* maybeNode = *reinterpret_cast<void**>(static_cast<uint8_t*>(childComp) + off);
                    if (maybeNode)
                    {
                        auto itP = g_pendingByNode.find(maybeNode);
                        if (itP != g_pendingByNode.end() && !itP->second.materialized)
                        {
                            itP->second.materialized = true;
                            itP->second.childComp = childComp;
                            spdlog::debug("[PENDING] materialized via CLC: nodeText={} childComp={} portPtr={}",
                                          maybeNode, childComp, portPtr);
                        }
                    }
                }
                else
                {
                    spdlog::debug("[PENDING] ChildComp not readable ptr");
                }
            }

            Prove_NodeTextComponentIdentity(childComp);
            CaptureAttachCaller(childComp);

            spdlog::debug("[CLC] childComp={} parentComp={} portPtr={}", childComp, parentComp, portPtr);

            ConnectLayoutComponent(childComp, parentComp, portPtr);
        }

        void __fastcall ConnectLayoutUtilityComponentHook(void* childComp, void* parentComp, uint32_t portSid)
        {
            void* resolvedPort = nullptr;
            void*** vt = reinterpret_cast<void***>(parentComp);
            if (IsReadablePtr(vt) && IsReadablePtr(vt[0]))
            {
                using FnGetPortBySid = void* (__fastcall*)(void*, uint32_t);
                FnGetPortBySid fn = reinterpret_cast<FnGetPortBySid>(vt[0][3]); // +0x18
                if (fn) resolvedPort = fn(parentComp, portSid);
            }
            spdlog::debug(
                "[CLU] childComp={} vt(child)=0x{:016X} parentComp={} vt(parent)=0x{:016X} portSid=#{:08X} resolvedPort={}",
                childComp, (uint64_t)VT(childComp), parentComp, (uint64_t)VT(parentComp), portSid, resolvedPort);

            ConnectLayoutUtilityComponent(childComp, parentComp, portSid);
        }

        void __fastcall ConnectChildWindowToNodeHook(void* window, void* windowHandle, void* parentComp, void* portPtr)
        {
            // Resolve slotObj
            uint32_t head = *(uint32_t*)((uint8_t*)window + 0x50);
            uint8_t* base = *(uint8_t**)((uint8_t*)window + 0x60);
            void* slotObj = nullptr;
            for (uint32_t it = head; it != 0xFFFFFFFF;)
            {
                uint8_t* entry = base + size_t(it) * 0x10;
                void* obj = *(void**)entry;
                if (obj && *(void**)obj == windowHandle)
                {
                    slotObj = obj;
                    break;
                }
                it = *(uint32_t*)(entry + 0x0C);
            }

            MaybeHookFactorySlotForHandle(windowHandle); // gated

            FTLSGuard tls(slotObj, parentComp, portPtr, windowHandle);

            ConnectChildWindowToNode(window, windowHandle, parentComp, portPtr);

            HandleLink link{};
            link.parentWindow = window;
            link.slotObj = nullptr; // left as-is; your earlier code fills it before
            link.parentComp = parentComp;
            link.portNode = portPtr;
            link.handle = windowHandle;
            link.wf = windowHandle;
            g_linkByHandle[windowHandle] = link;

            Anchor a{};
            a.slotObj = nullptr;
            a.parentComp = parentComp;
            a.portNode = portPtr;
            a.windowHandle = windowHandle;
            a.windowFunction = windowHandle;
            a.windowSig = ComputeWindowSig_direct(parentComp, portPtr, windowHandle);
            g_anchorByWindowSig[a.windowSig] = a;
            g_anchorByPort[PortKey{parentComp, portPtr}] = a;

            auto itP = g_pendingInjectByPort.find(PortKey{parentComp, portPtr});
            if (itP != g_pendingInjectByPort.end())
            {
                const std::string text = itP->second;
                g_pendingInjectByPort.erase(itP);
                CreatePendingForLink(link, text.c_str()); // do NOT attach now
            }
        }

        void __fastcall ConnectChildWindowToRootHook(void* window, void* windowHandle)
        {
            void* parentComp = *(void**)((uint8_t*)window + 0x28);
            void* portPtr = parentComp ? (void*)((uint8_t*)parentComp + 0x60) : nullptr;

            void* slotObj = nullptr;
            if (parentComp)
            {
                uint32_t head = *(uint32_t*)((uint8_t*)window + 0x50);
                uint8_t* base = *(uint8_t**)((uint8_t*)window + 0x60);
                for (uint32_t it = head; it != 0xFFFFFFFF;)
                {
                    uint8_t* entry = base + size_t(it) * 0x10;
                    void* obj = *(void**)entry;
                    if (obj && *(void**)obj == windowHandle)
                    {
                        slotObj = obj;
                        break;
                    }
                    it = *(uint32_t*)(entry + 0x0C);
                }
            }

            MaybeHookFactorySlotForHandle(windowHandle); // gated
            FTLSGuard tls(slotObj, parentComp, portPtr, windowHandle);

            ConnectChildWindowToRoot(window, windowHandle);
        }

        void* __fastcall GetConnectModelHook(void* self /*ModelNodeConnection**/, void* outTransform /*=nullptr*/)
        {
            auto ret = GetConnectModel(self, outTransform);
            spdlog::info("[GetConnectModel] model={} self={} outTransform={}", ret, self, outTransform);
            return ret;
        }

        void __fastcall ConnectWindowToParentHook(void* windowFunction, void* parentComp, void* portPtr)
        {
            ConnectWindowToParent(windowFunction, parentComp, portPtr);
        }

        void __fastcall SetModelNodeTextDisplayWidthHook(void* nodeText, float width)
        {
            SetModelNodeTextDisplayWidth(nodeText, width);
        }

        void __fastcall SetModelNodeTextDisplayHeightHook(void* nodeText, float height)
        {
            SetModelNodeTextDisplayHeight(nodeText, height);
        }

        bool __fastcall GetModelNodeWorldVisibilityHook(const void* node)
        {
            return GetModelNodeWorldVisibility(node);
        }

        void __fastcall BuildTextAreaPackHook(void* modelNodeText, TextAreaPack* out)
        {
            BuildTextAreaPack(modelNodeText, out);
        }

        int __fastcall AttachTextAndFinalizeHook(void* owner, void* container, void* node, void* unitsCtx)
        {
            return AttachTextAndFinalize(owner, container, node, unitsCtx);
        }

        void __fastcall ApplyTextAndMeasureHook(void* act, void* node, void* unitsCtx, void* fmtCtx)
        {
            return ApplyTextAndMeasure(act, node, unitsCtx, fmtCtx);
        }

        void __fastcall RunAnalysisHook(ActSetText* self)
        {
            RunAnalysis(self);
        }

        void __fastcall SetModelNodeTextDisplayAreaWidthOffsetHook(void* nodeText, float addWidth, float addOffset)
        {
            SetModelNodeTextDisplayAreaWidthOffset(nodeText, addWidth, addOffset);
        }

        void __fastcall LayoutConnectHook(void* uiUtil, void* windowIface,
                                          uint64_t sidA, uint64_t sidB,
                                          uint64_t sidModel, uint64_t sidPort)
        {
            LayoutConnect(uiUtil, windowIface, sidA, sidB, sidModel, sidPort);
        }

        void* __fastcall WindowCreateHook(const void* rc, const void* name, uint32_t flags,
                                          void* parent, uint16_t zOrder, uint32_t opt6, uint32_t opt7)
        {
            return WindowCreate(rc, name, flags, parent, zOrder, opt6, opt7);
        }

        void* __fastcall GetLayoutComponentHook(void* self)
        {
            auto retComponent = GetLayoutComponent(self);
            // spdlog::debug("[LAYOUTCOMPONENT] retComponent={} self={}", retComponent, self);
            return retComponent;
        }

        // Phase tick: hotkeys
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);
            spdlog::info("[UPDATE PHASE UI] phase={}", phase);


            // process any deferred nodes whose components now exist
            ProcessPendingsTick();

            if (GetAsyncKeyState(VK_F8) & 1) { DumpAnchors(); }
            if (GetAsyncKeyState(VK_F9) & 1) { DumpAttachCandidates(); }
            if (GetAsyncKeyState(VK_F10) & 1) { DumpProofSummary(); }

            if (GetAsyncKeyState(VK_F7) & 1)
            {
                bool fired = false;
                for (uint64_t want : g_targetSig64s)
                {
                    auto it = g_anchorByWindowSig.find(want);
                    if (it != g_anchorByWindowSig.end())
                    {
                        BeginInject_ByWindowSig(want, "Hello World");
                        fired = true;
                        break;
                    }
                }
                if (!fired && !g_anchorByWindowSig.empty())
                {
                    uint64_t want = g_anchorByWindowSig.begin()->first;
                    BeginInject_ByWindowSig(want, "Hello World");
                }
            }
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
            CREATE_HOOK(GetTextUnitsInternal)
            CREATE_HOOK(SetTextUnit)
            CREATE_HOOK(GraphUpdate)
            CREATE_HOOK(GetUixLayout)
            CREATE_HOOK(GetGlobalUixUtility)

            CREATE_HOOK(ConnectLayoutComponent)
            CREATE_HOOK(ConnectLayoutUtilityComponent)
            CREATE_HOOK(ConnectChildWindowToNode)
            CREATE_HOOK(ConnectChildWindowToRoot)
            CREATE_HOOK(ConnectWindowToParent)
            CREATE_HOOK(LayoutConnect)

            CREATE_HOOK(CreateBoxText)
            CREATE_HOOK(DeleteTextUnit)
            CREATE_HOOK(GetConnectModel)

            CREATE_HOOK(SetModelNodeTextDisplayWidth)
            CREATE_HOOK(SetModelNodeTextDisplayHeight)
            CREATE_HOOK(GetModelNodeWorldVisibility)
            CREATE_HOOK(SetModelNodeTextDisplayAreaWidthOffset)

            CREATE_HOOK(BuildTextAreaPack)
            CREATE_HOOK(AttachTextAndFinalize)
            CREATE_HOOK(ApplyTextAndMeasure)
            CREATE_HOOK(RunAnalysis)

            CREATE_HOOK(WindowCreate)
            CREATE_HOOK(GetLayoutComponent)

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
            ENABLEHOOK(GetTextUnitsInternal)
            ENABLEHOOK(SetTextUnit)
            ENABLEHOOK(GraphUpdate)
            ENABLEHOOK(GetUixLayout)
            ENABLEHOOK(GetGlobalUixUtility)

            ENABLEHOOK(ConnectLayoutComponent)
            ENABLEHOOK(ConnectLayoutUtilityComponent)
            ENABLEHOOK(ConnectChildWindowToNode)
            ENABLEHOOK(ConnectChildWindowToRoot)
            ENABLEHOOK(ConnectWindowToParent)
            ENABLEHOOK(LayoutConnect)

            ENABLEHOOK(CreateBoxText)
            ENABLEHOOK(DeleteTextUnit)
            ENABLEHOOK(GetConnectModel)

            ENABLEHOOK(SetModelNodeTextDisplayWidth)
            ENABLEHOOK(SetModelNodeTextDisplayHeight)
            ENABLEHOOK(GetModelNodeWorldVisibility)
            ENABLEHOOK(SetModelNodeTextDisplayAreaWidthOffset)

            ENABLEHOOK(BuildTextAreaPack)
            ENABLEHOOK(AttachTextAndFinalize)
            ENABLEHOOK(ApplyTextAndMeasure)
            ENABLEHOOK(RunAnalysis)

            ENABLEHOOK(WindowCreate)
            ENABLEHOOK(GetLayoutComponent)

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
