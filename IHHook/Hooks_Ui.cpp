//19:58 03/11/25
// Hooks_Ui.cpp — Add-our-own Window + inject UiModelText (F7)  |  ViewTree (F8)

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

#include <string>

namespace IHHook
{
    namespace Hooks_Ui
    {
        // -----------------------------------------------------------------------------
        // Globals
        // -----------------------------------------------------------------------------
        static std::mutex g_mx;

        // -----------------------------------------------------------------------------
        // TARGET LAYOUT SIGNATURES (fill with the one(s) you want)
        // -----------------------------------------------------------------------------
        // How to get: run with this patch, open the HUD/layout you want, press F8 and copy the
        // printed "sig64=..." for the layout you care about, then put it here.
        
        // Known layout SIDs you want to target (your originals)
        static std::unordered_set<uint64_t> g_targetKnownLayoutSids = {
            0x6E6A53858C7D348A, // Main Menu
            0xF9325CE34EBD7F47, // HUD
            0xE350B3CA76A89176,
            0x06B9B0CB69982096,
            0xDA11FACDB2201229
        };

        // globals
        static std::vector<void*> g_ourInjects;

        static std::unordered_map<uint64_t, uint32_t> g_lastPortSidBySig; // sig64 -> sidPort

        // windowIface -> layout, learned via GetUixLayout
        static std::unordered_map<void*, void*> g_layoutByWindowIface;

        // known SID -> computed modelSig observed on that layout
        static std::unordered_map<uint64_t, uint64_t> g_knownSidToComputedSig;


        // --- Unified anchor type + maps ---
        struct Anchor
        {
            void* owner{}; // windowFunction / owner if we learned one
            void* parentComp{}; // the parent component we’ll attach under
            void* portField{}; // address of (parent+0x60)
            void* portVal{}; // value at *(parent+0x60) when learned
        };

        // Observed layouts/models
        static std::unordered_map<void*, uint64_t> g_sigByLayout; // layout -> sig64
        static std::unordered_map<void*, void*> g_primaryModelByLayout; // layout -> model
        static std::unordered_map<void*, uint64_t> g_sigByModel; // model  -> sig64
        static std::unordered_map<void*, void*> g_layoutByModel; // model  -> layout
        static std::unordered_map<void*, uint64_t> g_currentSigByLayout; // layout -> sig64 (active)

        // Track our own nodes to avoid “learning” from our own connects
        static std::unordered_set<void*> g_ourNodes;

        // Harvested creation context for safe NewUiModelText
        static std::atomic<void*> g_lastTextCreationCtx{nullptr};
        static std::atomic<uint32_t> g_lastTextSceneStr{0};

        static std::unordered_map<uint64_t, Anchor> g_anchorBySig; // sig64 -> Anchor
        static std::unordered_map<void*, Anchor> g_anchorForLayout; // layout -> Anchor (borrowable)

        static inline void* Field60Addr(void* parent)
        {
            return parent ? (void*)((uint8_t*)parent + 0x60) : nullptr;
        }

        static inline void* ReadField60(void* parent)
        {
            void* f = Field60Addr(parent);
            return f ? *(void**)f : nullptr;
        }

        static inline bool Field60Matches(void* parent, void* expectedVal)
        {
            return ReadField60(parent) == expectedVal;
        }


        // -----------------------------------------------------------------------------
        // Utils
        // -----------------------------------------------------------------------------

        static inline uint64_t Fnv1a64(const void* data, size_t len)
        {
            const uint8_t* p = static_cast<const uint8_t*>(data);
            uint64_t h = 1469598103934665603ull;
            for (size_t i = 0; i < len; ++i)
            {
                h ^= p[i];
                h *= 1099511628211ull;
            }
            return h;
        }

        static inline uint64_t RebasedPtr(const void* p)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.AllocationBase)
                return (uint64_t)((uintptr_t)p - (uintptr_t)mbi.AllocationBase);
            return (uint64_t)(uintptr_t)p;
        }

        // Compute sig64 from vtable samples of nodes in a model (ASLR-invariant)
        static uint64_t ComputeLayoutSigFromModel(void* model, uint32_t sampleMax = 128)
        {
            if (!model) return 0;
            std::vector<uint64_t> parts;
            parts.reserve(sampleMax);
            for (int i = 0; i < 4096 && (uint32_t)parts.size() < sampleMax; ++i)
            {
                void* n = GetModelNodeFromIndex(model, i);
                if (!n) break;
                void** vtbl = *reinterpret_cast<void***>(n);
                parts.push_back(RebasedPtr(vtbl));
            }
            if (parts.empty()) return 0;
            std::sort(parts.begin(), parts.end());
            if (parts.size() > sampleMax) parts.resize(sampleMax);
            return Fnv1a64(parts.data(), parts.size() * sizeof(uint64_t));
        }

        static void RememberOurNode(void* n){
            if(!n) return;
            std::lock_guard<std::mutex> _l(g_mx);
            g_ourNodes.insert(n);
            g_ourInjects.push_back(n);
        }

        static bool IsOurNode(void* n)
        {
            std::lock_guard<std::mutex> _l(g_mx);
            return g_ourNodes.count(n) != 0;
        }

        // Optional: tweak text; safe to omit if you just want it visible
        // replace your UpdateTextForNode with this
        static void UpdateTextForNode(void* uix, void* node, const char* s = "Hello World!")
        {
            if (!uix || !node) return;

            // 1) Get a reusable text unit and configure it (size/flags as you like)
            void* unit = GetTextUnits(0);               // engine-provided text unit pool
            if (unit) {
                // flags/p3/p4/p7/p8 are game-specific; these “vanilla-ish” values work broadly
                SetTextUnit(unit, (char*)s, /*flags=*/1, /*p3=*/0, /*p4=*/0,
                            /*size=*/28.0f, /*tracking=*/0.0f, /*p7=*/0, /*p8=*/0);
                SetTextUnitsForModelNodeText(uix, node, unit, /*unitId=*/0);
            } else {
                // fallback: some builds still honor direct string set
                SetTextForModelNodeText(uix, node, nullptr, s, /*isLocalized=*/false);
            }

            // 2) Make sure the engine flips the right visibility bit (wrapper takes the manager)
            SetNodeVisibilityWrapper(uix, node, true);

            // 3) Push above most HUD layers and make it legible
            SetModelNodePriority(uix, node, 1000);      // higher than your previous 240
            SetModelNodeTextFontSize(uix, node, 28.0f, 0.0f);
            SetModelNodeTextColorRGB(uix, node, 1.0f, 1.0f, 1.0f);
        }

        static uint64_t PickActiveTargetSig()
        {
            std::lock_guard<std::mutex> _l(g_mx);

            // 1) direct match (computed sig explicitly listed)
            for (auto& kv : g_currentSigByLayout)
                if (kv.second && g_targetKnownLayoutSids.count(kv.second))
                    return kv.second;

            // 2) alias match (known layout SID -> computed sig observed on this run)
            for (auto& kv : g_knownSidToComputedSig) {
                const uint64_t computed = kv.second;
                for (auto& k2 : g_currentSigByLayout)
                    if (k2.second == computed)
                        return computed;
            }

            return 0;
        }

        static void* FindLayoutForSig_NoLock(uint64_t sig) {
            for (auto& kv : g_sigByLayout) if (kv.second == sig) return kv.first;
            return nullptr;
        }
        
        static void* FindLayoutForSig(uint64_t sig) { // existing external API
            std::lock_guard<std::mutex> _l(g_mx);
            return FindLayoutForSig_NoLock(sig);
        }

        static void BindAnchorToActiveSigAndLayout(void* parentComp, const char* srcTag, void* ownerHint = nullptr)
        {
            if (!parentComp) return;

            const auto field = Field60Addr(parentComp);
            const auto val   = ReadField60(parentComp);
            const uint64_t sig = PickActiveTargetSig();
            if (!sig) { spdlog::debug("[ANCHOR] {}: no active target; suppress", srcTag); return; }

            std::lock_guard<std::mutex> _l(g_mx);
            auto& a = g_anchorBySig[sig];
            a.parentComp = parentComp;
            a.portField  = field;
            a.portVal    = val;
            if (ownerHint && !a.owner) a.owner = ownerHint;

            if (void* layout = FindLayoutForSig_NoLock(sig))  // <-- no-lock helper
                g_anchorForLayout[layout] = a;

            spdlog::info("[ANCHOR] {}: sig=0x{:016X} parent={} field={} val={} owner={}",
                         srcTag, sig, parentComp, field, val, a.owner);
        }

        // Borrow an anchor previously seen on the same layout
        static bool TryBorrowAnchorFromLayout(uint64_t sig, Anchor& out)
        {
            std::lock_guard<std::mutex> _l(g_mx);
            if (void* layout = FindLayoutForSig_NoLock(sig)) {
                auto it = g_anchorForLayout.find(layout);
                if (it != g_anchorForLayout.end() && it->second.parentComp && it->second.portField) {
                    if (Field60Addr(it->second.parentComp) == it->second.portField) {
                        out = it->second;
                        return true;
                    }
                }
            }
            return false;
        }

        // -----------------------------------------------------------------------------
        // Hooks
        // -----------------------------------------------------------------------------

        // text hooks
        void __fastcall SetTextForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, const char* rawText,
                                                    bool isLocalized)
        {
            SetTextForModelNodeText(uix, nodeText, textUnit, rawText, isLocalized);
        }

        void __fastcall SetTextUnitsForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, uint64_t unitId)
        {
            SetTextUnitsForModelNodeText(uix, nodeText, textUnit, unitId);
        }

        bool __fastcall SetTextUnitsHook(void* nodeText, void* textUnit, uint64_t stringId)
        {
            bool r = SetTextUnits(nodeText, textUnit, stringId);
            return r;
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

        void* __fastcall NodeConnectShimHook(void* owner, void* parentComp, void* portPtr, void* childNode)
        {
            if (!IsOurNode(childNode))
            {
                BindAnchorToActiveSigAndLayout(parentComp, "NodeConnectShim", owner);
            }
            return NodeConnectShim(owner, parentComp, portPtr, childNode);
        }

        // Model discovery
        void* __fastcall GetModelWrapperHook(void* layout, void** outModel, uint32_t wantRoot)
        {
            void* ret = GetModelWrapper(layout, outModel, wantRoot);

            void* model = nullptr;
            if (ret && GetModelNodeFromIndex(ret, 0)) model = ret;
            else if (outModel && *outModel && GetModelNodeFromIndex(*outModel, 0)) model = *outModel;

            if (model)
            {
                const uint64_t sig = ComputeLayoutSigFromModel(model);
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    g_sigByLayout[layout] = sig;
                    g_sigByModel[model] = sig;
                    g_layoutByModel[model] = layout;
                    g_primaryModelByLayout[layout] = model;
                    g_currentSigByLayout[layout] = sig;
                }
                if (g_targetKnownLayoutSids.count(sig))
                    spdlog::info("[SIG] layout={} model={} sig64=0x{:016X}  <TARGET>", layout, model, sig);
                else
                    spdlog::debug("[SIG] layout={} model={} sig64=0x{:016X}", layout, model, sig);
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
                // purge from sig->anchor
                for (auto it = g_anchorBySig.begin(); it != g_anchorBySig.end(); ) {
                    if (it->second.parentComp == self) it = g_anchorBySig.erase(it);
                    else ++it;
                }
                // purge from layout->anchor
                for (auto it = g_anchorForLayout.begin(); it != g_anchorForLayout.end(); ) {
                    if (it->second.parentComp == self) it = g_anchorForLayout.erase(it);
                    else ++it;
                }
            }
            OnLayoutComponentDestroy(self);
        }

        // Creation ctx harvest
        void* __fastcall NewUiModelTextHook(uint32_t sceneStr, void* creationCtx, void* a2, void* a3)
        {
            if (creationCtx) g_lastTextCreationCtx.store(creationCtx, std::memory_order_relaxed);
            if (sceneStr) g_lastTextSceneStr.store(sceneStr, std::memory_order_relaxed);
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
            if (layout) {
                std::lock_guard<std::mutex> _l(g_mx);
                g_layoutByWindowIface[(void*)windowIface] = layout;
            }
            return layout;
        }

        // Window / layout connects (FIELD route)
        // NOTE: If your typedefs expose an extra leading 'this' for a UI utility, pass it as ownerHint below.
        void __fastcall ConnectLayoutComponentHook(void* childComp, void* parentComp, void* portComp)
        {
            if (ReadField60(parentComp) == portComp)
                BindAnchorToActiveSigAndLayout(parentComp, "ConnectLayoutComponent");
            ConnectLayoutComponent(childComp, parentComp, portComp);
        }

        void __fastcall ConnectLayoutUtilityComponentHook(void* childComp, void* parentComp, uint32_t portSid)
        {
            ConnectLayoutUtilityComponent(childComp, parentComp, portSid);
        }

        void __fastcall ConnectChildWindowToNodeHook(void* window, void* windowHandle, void* parentComp, void* portPtr)
        {
            if (ReadField60(parentComp) == portPtr)
                BindAnchorToActiveSigAndLayout(parentComp, "ConnectChildWindowToNode", window);
            ConnectChildWindowToNode(window, windowHandle, parentComp, portPtr);
        }

        void __fastcall ConnectWindowToParentHook(void* windowFunction, void* parentComp, void* portPtr)
        {
            if (ReadField60(parentComp) == portPtr)
                BindAnchorToActiveSigAndLayout(parentComp, "ConnectWindowToParent", windowFunction);
            ConnectWindowToParent(windowFunction, parentComp, portPtr);
        }

        void __fastcall LayoutConnectHook(void* uiUtil, void* windowIface,
                                          uint64_t sidA, uint64_t sidB,
                                          uint64_t sidModel, uint64_t sidPort)
        {
            // keep your debug line
            spdlog::debug("[LAYOUTCONNECT] wi={} sA=#{:08X} sB=#{:08X} sModel=#{:08X} sPort=#{:08X}",
                          windowIface, (uint32_t)sidA, (uint32_t)sidB, (uint32_t)sidModel, (uint32_t)sidPort);

            // NEW: learn alias when this is one of our known targets

            if (uint64_t sig = PickActiveTargetSig())
                g_lastPortSidBySig[sig] = (uint32_t)sidPort;

            if (g_targetKnownLayoutSids.count(sidModel)) {
                void* layout = nullptr;
                uint64_t computed = 0;
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    auto itL = g_layoutByWindowIface.find(windowIface);
                    if (itL != g_layoutByWindowIface.end()) {
                        layout = itL->second;
                        auto itS = g_currentSigByLayout.find(layout);
                        if (itS != g_currentSigByLayout.end())
                            computed = itS->second;
                    }
                }
                if (layout && computed) {
                    g_knownSidToComputedSig[sidModel] = computed;
                    spdlog::info("[ALIAS] modelSID=#{:08X} -> computedSig=0x{:016X} (layout={})",
                                 (uint32_t)sidModel, computed, layout);
                } else {
                    spdlog::debug("[ALIAS] no layout/sig yet for modelSID=#{:08X}", (uint32_t)sidModel);
                }
            }

            LayoutConnect(uiUtil, windowIface, sidA, sidB, sidModel, sidPort);
        }

        // Phase tick: update text & hotkeys
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);

            // Hotkeys
            static SHORT prev[256] = {};
            auto just = [&](int vk)
            {
                SHORT s = GetAsyncKeyState(vk);
                bool now = (s & 0x8000) != 0;
                bool was = (prev[vk] & 0x8000) != 0;
                prev[vk] = s;
                return now && !was;
            };

            if (just(VK_F7))
            {
                spdlog::warn("[HK] F7 -> inject…");

                do
                {
                    const uint64_t sig = PickActiveTargetSig();
                    if (!sig)
                    {
                        spdlog::warn("[INJECT] No active target visible.");
                        break;
                    }

                    Anchor a{};
                    {
                        std::lock_guard<std::mutex> _l(g_mx); // <-- add
                        auto it = g_anchorBySig.find(sig);
                        if (it != g_anchorBySig.end() && it->second.parentComp && it->second.portField)
                        {
                            a = it->second;
                            spdlog::info("[INJECT] using exact sig anchor 0x{:016X}", sig);
                        }
                    }
                    if (!a.parentComp)
                    {
                        if (!TryBorrowAnchorFromLayout(sig, a))
                        {
                            spdlog::warn("[INJECT] No valid anchor yet for 0x{:016X}. Interact with that UI first.",
                                         sig);
                            break;
                        } else {
                            spdlog::info("[INJECT] borrowed anchor from layout for 0x{:016X}", sig);
                        }
                    }

                    void* live = ReadField60(a.parentComp);
                    // Prefer the remembered portVal only if the field address still matches and the remembered value is non-null
                    void* port = (Field60Addr(a.parentComp) == a.portField && a.portVal) ? a.portVal : live;
                    if (!port) { spdlog::warn("[INJECT] Live port is null."); break; }

                    void* node = nullptr;
                    {
                        void* cc = g_lastTextCreationCtx.load(std::memory_order_relaxed);
                        uint32_t sc = g_lastTextSceneStr.load(std::memory_order_relaxed);
                        node = NewUiModelText(sc, cc, nullptr, nullptr);
                        if (!node) node = NewUiModelText(0, nullptr, nullptr, nullptr);
                    }
                    if (!node)
                    {
                        spdlog::warn("[INJECT] NewUiModelText failed.");
                        break;
                    }

                    RememberOurNode(node);
                    bool connected = false;

                    // 1) Utility route (build component + connect by port SID if we learned one)
                    if (!connected) {
                        auto it = g_lastPortSidBySig.find(sig);
                        if (it != g_lastPortSidBySig.end()) {
                            spdlog::info("[INJECT] Using ConnectLayoutUtilityComponent with sidPort=#{:08X}", it->second);
                            ConnectLayoutUtilityComponent(/*childComp=*/node, /*parentComp=*/a.parentComp, /*portSid=*/it->second);
                            connected = true;
                        }
                    }

                    // 2) Fallback: your existing port-value/port-field attempt via NodeConnectShim
                    if (!connected) {
                        spdlog::info("[INJECT] Falling back to NodeConnectShim.");
                        NodeConnectShim(a.owner, a.parentComp, port, node);
                        connected = true;
                    }

                    // After connecting, *ensure* it draws something:
                    if (auto** pp = GetGlobalUixUtility()) {
                        void* uix = *pp;
                        bool vis = IsNodeVisible(uix, node);
                        spdlog::info("[INJECT] post-connect IsNodeVisible(uix,node)={}", vis);
                    }

                    if (auto** pp = GetGlobalUixUtility())
                        if (void* uix = *pp)
                        {
                            SetNodeVisibility(node, true);
                            SetModelNodePriority(uix, node, 240);
                            SetModelNodeTextFontSize(uix, node, 28.0f, 0.0f);
                            SetModelNodeTextColorRGB(uix, node, 1.0f, 1.0f, 1.0f);
                            UpdateTextForNode(uix, node);
                        }
                }
                while (false);
            }

            if (just(VK_F8))
            {
                spdlog::info("[HK] F8 -> dump status");

                const uint64_t sig = PickActiveTargetSig();
                spdlog::info("[INJECT] active target sig=0x{:016X}", sig);


                // Layouts + sigs
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    spdlog::info("[DUMP] ===== Layouts (sig64) =====");
                    for (auto& kv : g_sigByLayout)
                    {
                        const bool target = g_targetKnownLayoutSids.count(kv.second) != 0;
                        spdlog::info("[DUMP] layout={} sig64=0x{:016X}{}", kv.first, kv.second,
                                     target ? "  <TARGET>" : "");
                    }
                    spdlog::info("[DUMP] ===== Current per-layout sig =====");
                    for (auto& kv : g_currentSigByLayout)
                    {
                        const bool target = g_targetKnownLayoutSids.count(kv.second) != 0;
                        spdlog::info("[DUMP] layout={} currentSig=0x{:016X}{}", kv.first, kv.second,
                                     target ? "  <TARGET>" : "");
                    }
                    spdlog::info("[DUMP] ===== Anchors by sig =====");
                    for (auto& kv : g_anchorBySig)
                    {
                        const bool target = g_targetKnownLayoutSids.count(kv.first) != 0;
                        const Anchor& a = kv.second;
                        spdlog::info("[DUMP] sig64=0x{:016X} owner={} parent={} field={} val={}{}",
                                     kv.first, a.owner, a.parentComp, a.portField, a.portVal,
                                     target ? "  <TARGET>" : "");
                    }
                    spdlog::info("[DUMP] ===== Anchors by layout =====");
                    for (auto& kv : g_anchorForLayout)
                    {
                        const void* layout = kv.first;
                        const uint64_t sig = g_sigByLayout.count((void*)layout) ? g_sigByLayout[(void*)layout] : 0;
                        const bool target = g_targetKnownLayoutSids.count(sig) != 0;
                        const Anchor& a = kv.second;
                        spdlog::info("[DUMP] layout={} sig64=0x{:016X} owner={} parent={} field={} val={}{}",
                                     layout, sig, a.owner, a.parentComp, a.portField, a.portVal,
                                     target ? "  <TARGET LAYOUT>" : "");
                    }
                    if (!g_ourInjects.empty()) {
                        if (auto** pp = GetGlobalUixUtility()) if (void* uix = *pp) {
                            spdlog::info("[DUMP] ===== Our injected nodes =====");
                            for (void* n : g_ourInjects) {
                                bool vis = IsNodeVisible(uix, n);
                                spdlog::info("[DUMP] node={} visible={}", n, vis);
                            }
                        }
                    }
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
