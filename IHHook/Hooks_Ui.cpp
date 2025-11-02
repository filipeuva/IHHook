//11:48 02/11/25
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

// ---- SEH LEAF HELPERS (no RAII, no STL, nothrow-ish) ----
static __declspec(noinline) void* SafeLoadPtr(const void* p) {
    void* v = nullptr;
    __try { v = *(void* const*)p; }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = nullptr; }
    return v;
}

static __forceinline const void* ParentField60(void* parent) {
    return reinterpret_cast<const void*>(reinterpret_cast<uint8_t*>(parent) + 0x60);
}

static __declspec(noinline) void* SafeLoadParent60(void* parent) {
    return SafeLoadPtr(ParentField60(parent));
}

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
        static std::unordered_set<uint64_t> g_targetLayoutSigs = {
            // example placeholders — replace with your real ones once discovered via F8
            //0x6E6A53858C7D348A, // Main Menu?
            //0xF9325CE34EBD7F47, // HUD?
            //0x74E5E1FF080986D1, // iDroid?
            0xC2FA1C76BFC052FA, // last to load before Main Menu
            0x3DA77CCC5B61E7C7, //unknown ?
        };

        // Observed layouts/models
        static std::unordered_map<void*, uint64_t> g_sigByLayout; // layout -> sig64
        static std::unordered_map<void*, void*> g_primaryModelByLayout; // layout -> model
        static std::unordered_map<void*, uint64_t> g_sigByModel; // model  -> sig64
        static std::unordered_map<void*, void*> g_layoutByModel; // model  -> layout

        // “Currently visible” sigs per layout (updated via GetModelWrapper hook)
        static std::unordered_map<void*, uint64_t> g_currentSigByLayout; // layout -> sig64

        // Anchor we need for injection
        struct Anchor
        {
            void* owner{}; // learned from NodeConnectShim (preferred) or ownerHint
            void* parentComp{}; // parent layout component
            const void* portField{}; // pointer to the field (parent+0x60) if learned from Connect* route
            const void* portValue{}; // actual node pointer value (learned from shim or deref of field)
        };

        static std::unordered_map<uint64_t, Anchor> g_anchorBySig; // sig64 -> anchor

        // Backfill: (parentComp, portValue) -> owner (from any shim observed)
        static inline uint64_t HashTwoPtrs(void* a, const void* b)
        {
            uint64_t x = (uint64_t)(uintptr_t)a;
            uint64_t y = (uint64_t)(uintptr_t)b;
            // FNV-1a on the two pointers
            uint64_t h = 1469598103934665603ull;
            auto mix = [&](uint64_t v)
            {
                for (int i = 0; i < 8; i++)
                {
                    h ^= (uint8_t)(v & 0xFF);
                    h *= 1099511628211ull;
                    v >>= 8;
                }
            };
            mix(x);
            mix(y);
            return h;
        }

        static std::unordered_map<uint64_t, void*> g_ownerByParentPortValue; // key(parent,portValue) -> owner

        // Track our own nodes to avoid re-learning on our own connects
        static std::unordered_set<void*> g_ourNodes;

        // Harvested creation context (for safe NewUiModelText)
        static std::atomic<void*> g_lastTextCreationCtx{nullptr};
        static std::atomic<uint32_t> g_lastTextSceneStr{0};

        // Simple camo index to display (replace/update from your gameplay hook)
        static std::atomic<int> g_camoIndex{-1};

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
            {
                return (uint64_t)((uintptr_t)p - (uintptr_t)mbi.AllocationBase);
            }
            return (uint64_t)(uintptr_t)p; // fallback
        }

        // Stable sig64: sample node vtbls from model (ASLR-invariant via rebase)
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

        static void RememberOurNode(void* n)
        {
            if (!n) return;
            std::lock_guard<std::mutex> _l(g_mx);
            g_ourNodes.insert(n);
        }

        static bool IsOurNode(void* n)
        {
            std::lock_guard<std::mutex> _l(g_mx);
            return g_ourNodes.count(n) != 0;
        }

        static void UpdateTextForNode(void* uix, void* node)
        {
            if (!uix || !node) return;
            char buf[64];
            const int v = g_camoIndex.load();
            if (v >= 0) _snprintf_s(buf, _TRUNCATE, "Camo: %d", v);
            else _snprintf_s(buf, _TRUNCATE, "Camo: ?");
            SetTextForModelNodeText(uix, node, nullptr, buf, false);
            SetModelNodePriority(uix, node, 240);
            SetModelNodeTextFontSize(uix, node, 28.0f, 0.0f);
            SetModelNodeTextColorRGB(uix, node, 1.0f, 1.0f, 1.0f);
        }

        static void MaybeRefreshInjectedText()
        {
            static int prev = INT_MIN;
            const int v = g_camoIndex.load();
            if (v == prev) return;
            prev = v;
            if (auto** pp = GetGlobalUixUtility())
                if (void* uix = *pp) { (void)uix; /* refresh next creation; we don't hold a list here */ }
        }

        // Pick first ACTIVE target sig with anchor; else any learned target sig
        static uint64_t PickActiveTargetSig()
        {
            std::lock_guard<std::mutex> _l(g_mx);
            for (auto& kv : g_currentSigByLayout)
            {
                const uint64_t sig = kv.second;
                if (sig && g_targetLayoutSigs.count(sig) && g_anchorBySig.count(sig)) return sig;
            }
            for (auto s : g_targetLayoutSigs) if (g_anchorBySig.count(s)) return s;
            return 0;
        }

        // -----------------------------------------------------------------------------
        // Anchor learning helpers (field vs value) + validation
        // -----------------------------------------------------------------------------
        static void BindAnchor_FromField(uint64_t sig, void* ownerHint, void* parentComp, const void* portFieldPtr)
        {
            if (!sig || !parentComp || !portFieldPtr) return;

            const void* expectedField = ParentField60(parentComp);
            if (expectedField != portFieldPtr) {
                spdlog::debug("[ANCHOR] field-route: parent+0x60 mismatch (parent={} field={} expected={})",
                              parentComp, portFieldPtr, expectedField);
                // continue anyway
            }

            const void* val = SafeLoadParent60(parentComp); // <-- was __try deref

            {
                std::lock_guard<std::mutex> _l(g_mx);
                Anchor& a = g_anchorBySig[sig];
                a.parentComp = parentComp;
                a.portField  = expectedField;   // normalized to parent+0x60
                if (val && !a.portValue) a.portValue = val;
                if (ownerHint && !a.owner) a.owner = ownerHint;
            }

            spdlog::info("[ANCHOR] bound (Connect* field) sig=0x{:016X} parent={} field={} val={} owner={}",
                         sig, parentComp, expectedField, val, ownerHint);
        }
        static void BindAnchor_FromShim(uint64_t sig, void* owner, void* parentComp, const void* portValue)
        {
            if (!sig || !owner || !parentComp || !portValue) return;

            const void* field  = ParentField60(parentComp);
            const void* curVal = SafeLoadPtr(field); // <-- was __try

            {
                std::lock_guard<std::mutex> _l(g_mx);
                Anchor& a = g_anchorBySig[sig];
                a.parentComp = parentComp;
                a.portValue  = portValue; // authoritative from shim
                if (!a.portField) a.portField = field;
                a.owner = owner;
                g_ownerByParentPortValue[HashTwoPtrs(parentComp, portValue)] = owner;
            }

            spdlog::info("[ANCHOR] updated (NodeConnectShim) sig=0x{:016X} owner={} parent={} field={} val={} curVal={} match={}",
                         sig, owner, parentComp, field, portValue, curVal, (curVal == portValue));
        }

        // Choose a sig to bind to (prefer active target; else any current; else 0)
        static uint64_t PickSigForBinding()
        {
            std::lock_guard<std::mutex> _l(g_mx);
            for (auto& kv : g_currentSigByLayout)
            {
                if (g_targetLayoutSigs.count(kv.second)) return kv.second;
            }
            if (!g_currentSigByLayout.empty()) return g_currentSigByLayout.begin()->second;
            return 0;
        }

        static bool ValidateAnchor(const Anchor& a)
        {
            if (!a.parentComp) return false;

            const void* field = ParentField60(a.parentComp);
            const void* val   = SafeLoadParent60(a.parentComp); // <-- was __try

            if (a.portField && a.portField != field) {
                spdlog::warn("[ANCHOR] validate: parent+0x60 changed (have={} now={})", a.portField, field);
                return false;
            }
            if (a.portValue && val && a.portValue != val) {
                spdlog::warn("[ANCHOR] validate: field value changed (have={} now={})", a.portValue, val);
                return false;
            }
            return true;
        }

        // Try to backfill owner using (parent, current field value)
        static void TryBackfillOwner(Anchor& a)
        {
            if (a.owner) return;
            const void* val = SafeLoadParent60(a.parentComp); // <-- was __try
            if (!val) return;

            const uint64_t k = HashTwoPtrs(a.parentComp, val);
            auto it = g_ownerByParentPortValue.find(k);
            if (it != g_ownerByParentPortValue.end() && it->second) {
                a.owner = it->second;
                if (!a.portValue) a.portValue = val;
                spdlog::info("[ANCHOR] owner backfilled from map: owner={} parent={} val={}",
                             a.owner, a.parentComp, val);
            }
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
            return SetTextUnits(nodeText, textUnit, stringId);
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
            bool v = IsNodeVisible(anyMgr, node);
            return v;
        }

        // NodeConnectShim — authoritative owner + portValue (the node)
        void* __fastcall NodeConnectShimHook(void* owner, void* parentComp, void* portValue, void* childNode)
        {
            const bool ours = IsOurNode(childNode);

            const void* curVal = SafeLoadParent60(parentComp); // <-- was __try
            spdlog::debug("[SHIM] owner={} parent={} portValue={} curFieldVal={} match={}",
                          owner, parentComp, portValue, curVal, (curVal == portValue));

            if (!ours && owner && parentComp && portValue) {
                const uint64_t sig = PickSigForBinding();
                if (sig) BindAnchor_FromShim(sig, owner, parentComp, portValue);
            }
            return NodeConnectShim(owner, parentComp, portValue, childNode);
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
                if (g_targetLayoutSigs.count(sig))
                {
                    spdlog::info("[SIG] layout={} model={} sig64=0x{:016X}  <TARGET>", layout, model, sig);
                }
                else
                {
                    spdlog::debug("[SIG] layout={} model={} sig64=0x{:016X}", layout, model, sig);
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
            return layout;
        }

        // Window / layout connects (FIELD route)
        // NOTE: If your typedefs expose an extra leading 'this' for a UI utility, pass it as ownerHint below.
        void __fastcall ConnectLayoutComponentHook(void* childComp, void* parentComp, void* portFieldPtr)
        {
            const uint64_t sig = PickSigForBinding();
            if (sig) BindAnchor_FromField(sig, /*ownerHint*/nullptr, parentComp, portFieldPtr);
            ConnectLayoutComponent(childComp, parentComp, portFieldPtr);
        }

        void __fastcall ConnectLayoutUtilityComponentHook(void* childComp, void* parentComp, uint32_t portSid)
        {
            // No direct field ptr here; skip.
            ConnectLayoutUtilityComponent(childComp, parentComp, portSid);
        }

        void __fastcall ConnectChildWindowToNodeHook(void* window, void* windowHandle, void* parentComp,
                                                     void* portFieldPtr)
        {
            const uint64_t sig = PickSigForBinding();
            // We can treat 'window' as an ownerHint (same graph family), but NodeConnectShim remains authoritative.
            if (sig) BindAnchor_FromField(sig, /*ownerHint*/window, parentComp, portFieldPtr);
            ConnectChildWindowToNode(window, windowHandle, parentComp, portFieldPtr);
        }

        void __fastcall ConnectWindowToParentHook(void* windowFunction, void* parentComp, void* portFieldPtr)
        {
            const uint64_t sig = PickSigForBinding();
            if (sig) BindAnchor_FromField(sig, /*ownerHint*/windowFunction, parentComp, portFieldPtr);
            ConnectWindowToParent(windowFunction, parentComp, portFieldPtr);
        }


        void __fastcall LayoutConnectHook(void* uiUtil, void* windowIface, uint64_t sidA, uint64_t sidB,
                                          uint64_t sidModel, uint64_t sidPort)
        {
            spdlog::debug("[LAYOUTCONNECT] wi={} sA=#{:08X} sB=#{:08X} sModel=#{:08X} sPort=#{:08X}",
                          windowIface, (uint32_t)sidA, (uint32_t)sidB, (uint32_t)sidModel, (uint32_t)sidPort);
            LayoutConnect(uiUtil, windowIface, sidA, sidB, sidModel, sidPort);
        }

        // Phase tick: update text & hotkeys
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);
            MaybeRefreshInjectedText();

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
                spdlog::warn("[HK] F7 -> inject our UiModelText into active target layout");
                uint64_t sig = PickActiveTargetSig();
                if (!sig)
                {
                    spdlog::warn(
                        "[INJECT] No active target sig with a learned anchor yet. Show the target UI, interact, then try again.");
                }
                else
                {
                    Anchor a{};
                    {
                        std::lock_guard<std::mutex> _l(g_mx);
                        a = g_anchorBySig[sig];
                    }
                    if (!a.parentComp)
                    {
                        spdlog::warn("[INJECT] Anchor for sig=0x{:016X} missing parent.", sig);
                        return;
                    }
                    // Try to backfill owner if needed
                    if (!a.owner)
                    {
                        TryBackfillOwner(a);
                        if (!a.owner)
                        {
                            spdlog::warn("[INJECT] Anchor for sig=0x{:016X} has no owner yet.", sig);
                        }
                    }
                    // Validate parent/field/value consistency; also fill a.portValue from current field if missing
                    if (!ValidateAnchor(a))
                    {
                        spdlog::warn("[INJECT] Anchor for sig=0x{:016X} failed validation.", sig);
                        return;
                    }
                    if (!a.portValue) {
                        a.portValue = SafeLoadParent60(a.parentComp); // <-- was __try
                    }
                    if (!a.owner || !a.portValue)
                    {
                        spdlog::warn("[INJECT] Anchor incomplete for sig=0x{:016X} (owner={} val={}).",
                                     sig, a.owner, a.portValue);
                        return;
                    }

                    // Craft node
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
                        return;
                    }

                    RememberOurNode(node);
                    void* handle = NodeConnectShim(a.owner, a.parentComp, const_cast<void*>(a.portValue), node);
                    spdlog::info("[INJECT] NodeConnectShim -> handle={}", handle);
                    if (auto** pp = GetGlobalUixUtility()) if (void* uix = *pp) UpdateTextForNode(uix, node);

                    // Persist back any upgrades
                    {
                        std::lock_guard<std::mutex> _l(g_mx);
                        Anchor& dst = g_anchorBySig[sig];
                        if (!dst.owner) dst.owner = a.owner;
                        if (!dst.portField)dst.portField = a.portField;
                        if (!dst.portValue)dst.portValue = a.portValue;
                        if (!dst.parentComp) dst.parentComp = a.parentComp;
                    }
                }
            }

            if (just(VK_F8))
            {
                spdlog::info("[HK] F8 -> dump status");
                {
                    std::lock_guard<std::mutex> _l(g_mx);
                    spdlog::info("[DUMP] ===== Layouts (sig64) =====");
                    for (auto& kv : g_sigByLayout)
                    {
                        const bool target = g_targetLayoutSigs.count(kv.second) != 0;
                        spdlog::info("[DUMP] layout={} sig64=0x{:016X}{}", kv.first, kv.second,
                                     target ? "  <TARGET>" : "");
                    }
                    spdlog::info("[DUMP] ===== Current per-layout sig =====");
                    for (auto& kv : g_currentSigByLayout)
                    {
                        const bool target = g_targetLayoutSigs.count(kv.second) != 0;
                        spdlog::info("[DUMP] layout={} currentSig=0x{:016X}{}", kv.first, kv.second,
                                     target ? "  <TARGET>" : "");
                    }
                    spdlog::info("[DUMP] ===== Anchors by sig =====");
                    for (auto& kv : g_anchorBySig)
                    {
                        const bool target = g_targetLayoutSigs.count(kv.first) != 0;
                        spdlog::info("[DUMP] sig64=0x{:016X} owner={} parent={} field={} val={}{}",
                                     kv.first, kv.second.owner, kv.second.parentComp,
                                     kv.second.portField, kv.second.portValue,
                                     target ? "  <TARGET>" : "");
                    }
                }
                // Tiny "view" for any active target: list first 48 nodes’ re-based vtbls
                uint64_t sig = PickActiveTargetSig();
                if (sig)
                {
                    void* layout = nullptr;
                    void* model = nullptr;
                    {
                        std::lock_guard<std::mutex> _l(g_mx);
                        for (auto& kv : g_sigByLayout) if (kv.second == sig)
                        {
                            layout = kv.first;
                            break;
                        }
                        if (layout) model = g_primaryModelByLayout[layout];
                    }
                    if (model)
                    {
                        spdlog::info("[VIEW] layout={} model={} sig64=0x{:016X}", layout, model, sig);
                        for (int i = 0; i < 48; i++)
                        {
                            void* n = GetModelNodeFromIndex(model, i);
                            if (!n) break;
                            void** vtbl = *reinterpret_cast<void***>(n);
                            spdlog::info("[VIEW]  idx={:02d} node={} vtbl.rebased=0x{:016X}", i, n, RebasedPtr(vtbl));
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
