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
#include <winternl.h> // NTAPI, PVOID

#include "Hooks_Camo.h"
#pragma comment(lib, "ntdll") // not strictly required for GetProcAddress hook, harmless

namespace IHHook
{
    namespace Hooks_Ui
    {
        struct WindowInfo
        {
            fox::ui::Window* window{}; // fox::ui::Window*
            fox::ui::Window* parentWindow{}; // parent Window*
            fox::ui::WindowFunction* windowFunction{};
            fox::ui::WindowHandle* windowHandle{};
            std::vector<fox::ui::Layout*> layouts; // layouts owned by this window
            std::vector<fox::ui::Window*> children; // direct children in window graph

            fox::ui::Layout* attachLayout{}; // parent layout we hang from (if child)
            void*            attachAnchor{}; // portPtr / node / slot pointer

            std::string windowName;
        };

        struct ModelInfo
        {
            fox::ui::ModelFileHeader*             fileHeader{}; // *(model + 0x68)
            fox::StrCode32                        modelName{};  // NewUiModelSharedPtr name
            fox::StrCode                          pathCode64{}; // optional: fill if you ever hook GetPathCode64s
            std::vector<fox::ui::ModelNode*>      nodes;        // collected in ReadUiModelNodeHook
        };

        static std::unordered_map<fox::ui::Window*, WindowInfo> g_windows; // window* -> info
        static std::unordered_map<void*, fox::ui::Window*> g_windowFuncToWindow;
        static std::unordered_map<fox::ui::WindowHandle*, fox::ui::Window*> g_handleToWindow; // handle -> window
        static std::unordered_map<fox::ui::Layout*, fox::ui::Window*> g_layoutToWindow; // layout* -> window

        // NEW: layouts seen per handle (WindowInterface). We bind these to a Window*
        // as soon as we learn handle->window.
        static std::unordered_map<const fox::ui::WindowInterface*, std::vector<fox::ui::Layout*>> g_ifaceLayouts;   // key = WindowInterface*
        static std::unordered_map<fox::ui::WindowHandle*, std::vector<fox::ui::Layout*>> g_handleLayouts;

        static std::unordered_map<fox::ui::Model*, ModelInfo> g_modelInfo; // Model* -> info
        static std::unordered_map<fox::ui::ModelNode*, uint32_t> g_nodeNameByPtr; // ModelNode* -> StrCode32
        static std::unordered_map<fox::ui::ModelNode*, std::string> g_nodeTextByPtr; // ModelNode* -> last text

        static std::vector<fox::ui::Layout*> g_seenLayouts;
        static std::unordered_set<fox::ui::Layout*> g_seenLayoutsSet;
        static std::unordered_map<fox::ui::LayoutComponent*, fox::ui::Layout*> g_componentToLayout;

        static std::mutex g_uiMutex;

        // ---------------------------------------------------------------------
        // Hooked Utils TODO: Pass these to struct
        // ---------------------------------------------------------------------

        static uint32_t GetModelNodeCountRaw(fox::ui::Model* model)
        {
            if (!model) return 0;
            auto base = reinterpret_cast<uint8_t*>(model);
            return *reinterpret_cast<uint32_t*>(base + 0x90);
        }

        static fox::ui::ModelNode** GetModelNodeArrayTyped(fox::ui::Model* model)
        {
            if (!model) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(model);
            return *reinterpret_cast<fox::ui::ModelNode***>(base + 0x98);
        }

        static uint32_t GetModelCountRaw(fox::ui::Layout* layout)
        {
            if (!layout) return 0;
            auto base = reinterpret_cast<uint8_t*>(layout);
            return *reinterpret_cast<uint32_t*>(base + 0xC0);
        }

        static fox::ui::Model** GetModelArrayTyped(fox::ui::Layout* layout)
        {
            if (!layout) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(layout);
            return *reinterpret_cast<fox::ui::Model***>(base + 0xC8);
        }

        static fox::ui::Layout* GetWindowRootLayout(fox::ui::Window* window)
        {
            if (!window) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(window);
            return *reinterpret_cast<fox::ui::Layout**>(base + 0x28);
        }

        static std::string FoxStringToStd(const fox::String* s)
        {
            if (!s || !s->cString)
                return {};

            // Length is a 64-bit field, but negative values are sentinels.
            const auto raw = static_cast<int64_t>(s->length);

            // Reject sentinel / insane lengths outright.
            // These are not real strings.
            if (raw <= 0 || raw > 0x10000) // 64KB clamp
                return {};

            // Normal case: sane positive length.
            return std::string(s->cString, static_cast<size_t>(raw));
        }

        // ---------------------------------------------------------------------
        // Hooks
        // ---------------------------------------------------------------------

        static void SetLayoutOwner_NoLock(fox::ui::Layout* layout,
                                  fox::ui::Window* w,
                                  const char* reason)
        {
            if (!layout || !w)
                return;

            g_layoutToWindow[layout] = w;

            auto& info = g_windows[w];
            info.window = w;

            auto& lv = info.layouts;
            if (std::find(lv.begin(), lv.end(), layout) == lv.end())
                lv.push_back(layout);

            spdlog::info("[LAYOUT OWNER] layout={} window={} reason={}",
                         static_cast<const void*>(layout),
                         static_cast<const void*>(w),
                         reason ? reason : "");
        }
        
        static void BindHandleLayoutsToWindow_NoLock(fox::ui::WindowHandle* handle,
                                             fox::ui::Window* w)
        {
            if (!handle || !w)
                return;

            auto it = g_handleLayouts.find(handle);
            if (it == g_handleLayouts.end())
                return;

            auto& layouts = it->second;
            auto& info = g_windows[w];
            info.window       = w;
            info.windowHandle = handle;

            for (auto* L : layouts)
            {
                if (!L)
                    continue;

                SetLayoutOwner_NoLock(L, w, "BindHandleLayoutsToWindow");
            }
        }
        
        static void DumpModelNodes_Direct(void* modelPtr, const std::string& indent)
        {
            auto* model = reinterpret_cast<fox::ui::Model*>(modelPtr);
            if (!model) return;

            uint32_t count = GetModelNodeCountRaw(model);
            auto** nodes = GetModelNodeArrayTyped(model);

            spdlog::info(
                "{}[MODEL] model={} nodeCount={}",
                indent,
                static_cast<const void*>(model),
                count
            );

            if (!nodes) return;

            const std::string nodeIndent = indent + "  ";

            for (uint32_t i = 0; i < count; ++i)
            {
                auto* node = nodes[i];
                if (!node) continue;

                uint32_t nameSid = 0;
                std::string text;
                {
                    std::lock_guard<std::mutex> lock(g_uiMutex);

                    auto itName = g_nodeNameByPtr.find(node);
                    if (itName != g_nodeNameByPtr.end())
                        nameSid = itName->second;

                    auto itText = g_nodeTextByPtr.find(node);
                    if (itText != g_nodeTextByPtr.end())
                        text = itText->second;
                }

                std::string shortText = text;
                if (shortText.size() > 80)
                {
                    shortText.resize(80);
                    shortText += "...";
                }

                if (!shortText.empty())
                {
                    spdlog::info(
                        "{}[NODE] idx={} node={} name32=#{:08X} text=\"{}\"",
                        nodeIndent,
                        static_cast<int>(i),
                        static_cast<const void*>(node),
                        nameSid,
                        shortText
                    );
                }
                else
                {
                    spdlog::info(
                        "{}[NODE] idx={} node={} name32=#{:08X}",
                        nodeIndent,
                        static_cast<int>(i),
                        static_cast<const void*>(node),
                        nameSid
                    );
                }
            }
        }

        static void DumpLayoutModelsAndNodes()
        {
            std::vector<fox::ui::Layout*> layoutsCopy;
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                layoutsCopy = g_seenLayouts;
            }

            spdlog::info("========== UI LAYOUT / MODEL / NODE TREE ==========");
            spdlog::info("  layouts tracked: {}", layoutsCopy.size());

            for (auto* layout : layoutsCopy)
            {
                if (!layout)
                    continue;

                void** modelArr = nullptr;
                uint32_t mCount = 0;
                fox::ui::Window* ownerWindow = nullptr;
                std::string winName;

                {
                    std::lock_guard<std::mutex> lock(g_uiMutex);

                    auto* base = reinterpret_cast<uint8_t*>(layout);
                    modelArr = *reinterpret_cast<void***>(base + 0xC8);
                    mCount = *reinterpret_cast<uint32_t*>(base + 0xC0);

                    auto itW = g_layoutToWindow.find(layout);
                    if (itW != g_layoutToWindow.end())
                    {
                        ownerWindow = itW->second;
                        auto itInfo = g_windows.find(ownerWindow);
                        if (itInfo != g_windows.end())
                            winName = itInfo->second.windowName;
                    }
                }

                spdlog::info(
                    "[LAYOUT] layout={} modelArr={} modelCount={} ownerWindow={} windowName=\"{}\"",
                    static_cast<const void*>(layout),
                    static_cast<const void*>(modelArr),
                    mCount,
                    static_cast<const void*>(ownerWindow),
                    winName
                );

                if (!modelArr || !mCount)
                {
                    spdlog::info("  [MODEL] <none>");
                    continue;
                }

                for (uint32_t i = 0; i < mCount; ++i)
                {
                    void* modelPtr = modelArr[i];
                    if (!modelPtr)
                        continue;

                    spdlog::info(
                        "  [MODEL IDX] {} -> {}",
                        i,
                        static_cast<const void*>(modelPtr)
                    );

                    DumpModelNodes_Direct(modelPtr, "    ");
                }
            }

            spdlog::info("========== END UI LAYOUT / MODEL / NODE TREE ==========");
        }
        
        static bool IsKnownLayout_NoLock(fox::ui::Layout* layout)
        {
            if (!layout)
                return false;
            return g_seenLayoutsSet.find(layout) != g_seenLayoutsSet.end();
        }

        static void DumpLayoutForWindow(fox::ui::Layout* layout,
                                        fox::ui::Window* ownerWindow,
                                        const std::string& windowName,
                                        int depth)
        {
            if (!layout)
                return;
            
            // {
            //     std::lock_guard<std::mutex> lock(g_uiMutex);
            //     if (!IsKnownLayout_NoLock(layout))
            //     {
            //         spdlog::info("[LAYOUT DUMP SKIP] layout={} (not in seenLayoutsSet)",
            //                      static_cast<const void*>(layout));
            //         return;
            //     }
            // }
            
            auto* base = reinterpret_cast<uint8_t*>(layout);
            void** modelArr = *reinterpret_cast<void***>(base + 0xC8);
            uint32_t mCount = *reinterpret_cast<uint32_t*>(base + 0xC0);

            std::string indent(depth * 2, ' ');

            spdlog::info(
                "{}[LAYOUT] layout={} modelArr={} modelCount={} ownerWindow={} windowName=\"{}\"",
                indent,
                static_cast<const void*>(layout),
                static_cast<const void*>(modelArr),
                mCount,
                static_cast<const void*>(ownerWindow),
                windowName
            );

            if (!modelArr || !mCount)
            {
                spdlog::info("{}  [MODEL] <none>", indent);
                return;
            }

            for (uint32_t i = 0; i < mCount; ++i)
            {
                void* modelPtr = modelArr[i];
                if (!modelPtr)
                    continue;

                spdlog::info(
                    "{}  [MODEL IDX] {} -> {}",
                    indent,
                    i,
                    static_cast<const void*>(modelPtr)
                );

                DumpModelNodes_Direct(modelPtr, indent + "    ");
            }
        }

        static void DumpWindowRecursive(fox::ui::Window* w,
                                        const std::unordered_map<fox::ui::Window*, WindowInfo>& windows,
                                        int depth)
        {
            auto it = windows.find(w);
            if (it == windows.end())
                return;

            const WindowInfo& info = it->second;
            std::string indent(depth * 2, ' ');

            spdlog::info(
                "{}[WIN] window={} parent={} handle={} func={} name=\"{}\" anchorLayout={} anchorPort={}",
                indent,
                static_cast<const void*>(info.window),
                static_cast<const void*>(info.parentWindow),
                static_cast<const void*>(info.windowHandle),
                static_cast<const void*>(info.windowFunction),
                info.windowName,
                static_cast<const void*>(info.attachLayout),
                info.attachAnchor
            );

            // Layouts belonging to this window
            for (auto* layout : info.layouts)
            {
                DumpLayoutForWindow(layout, info.window, info.windowName, depth + 1);
            }

            // Recurse into children
            for (auto* child : info.children)
            {
                DumpWindowRecursive(child, windows, depth + 1);
            }
        }

        static void DumpWindowAndLayoutTree()
        {
            std::unordered_map<fox::ui::Window*, WindowInfo> windowsCopy;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                windowsCopy = g_windows; // value copy: safe snapshot
            }

            spdlog::info("========== UI WINDOW / LAYOUT / MODEL TREE ==========");
            spdlog::info("  windows tracked: {}", windowsCopy.size());

            // Root windows = no parent, or parent not in map
            for (auto& kv : windowsCopy)
            {
                fox::ui::Window* w = kv.first;
                const WindowInfo& info = kv.second;

                if (!info.parentWindow || windowsCopy.find(info.parentWindow) == windowsCopy.end())
                {
                    DumpWindowRecursive(w, windowsCopy, 0);
                }
            }

            spdlog::info("========== END UI WINDOW / LAYOUT / MODEL TREE ==========");
        }
        
        static void TrackLayout_NoLock(fox::ui::Layout* layout)
        {
            if (!layout) return;

            if (g_seenLayoutsSet.insert(layout).second)
            {
                g_seenLayouts.push_back(layout);
                spdlog::info("[TRACK LAYOUT] layout={}", static_cast<const void*>(layout));
            }
        }
        
        static void TrackLayout(fox::ui::Layout* layout)
        {
            if (!layout) return;

            std::lock_guard<std::mutex> lock(g_uiMutex);
            TrackLayout_NoLock(layout);
        }

        // Scan a layoutInfo blob for pointers that match known Layout*
        static std::vector<fox::ui::Layout*> ScanLayoutInfoForLayouts_NoLock(const void* layoutInfo)
        {
            std::vector<fox::ui::Layout*> out;
            if (!layoutInfo)
                return out;

            const uint8_t* base = reinterpret_cast<const uint8_t*>(layoutInfo);

            // Conservative scan range, can be extended if needed
            constexpr size_t kMaxScan = 0x80;

            for (size_t off = 0; off + sizeof(void*) <= kMaxScan; off += sizeof(void*))
            {
                auto candidate = *reinterpret_cast<fox::ui::Layout* const*>(base + off);
                if (!candidate)
                    continue;

                if (g_seenLayoutsSet.find(candidate) == g_seenLayoutsSet.end())
                    continue;

                if (std::find(out.begin(), out.end(), candidate) == out.end())
                    out.push_back(candidate);
            }

            return out;
        }

        static void DumpOrphanLayouts()
        {
            std::vector<fox::ui::Layout*> layoutsCopy;
            std::unordered_map<fox::ui::Layout*, fox::ui::Window*> layoutToWindowCopy;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                layoutsCopy       = g_seenLayouts;
                layoutToWindowCopy = g_layoutToWindow;
            }

            spdlog::info("========== ORPHAN LAYOUTS (no owning Window) ==========");
            spdlog::info("  orphans tracked: {} / {}", layoutsCopy.size() - layoutToWindowCopy.size(), layoutsCopy.size());
            
            for (auto* layout : layoutsCopy)
            {
                if (!layout)
                    continue;

                auto it = layoutToWindowCopy.find(layout);
                if (it != layoutToWindowCopy.end() && it->second)
                    continue; // already owned, skip here

                DumpLayoutForWindow(layout, nullptr, "<ORPHAN>", 0);
            }
            
            spdlog::info("========== END ORPHAN LAYOUTS ==========");
        }

        static void DumpUnifiedViewTree()
        {
            DumpWindowAndLayoutTree(); // Windows + their layouts + models + nodes
            DumpOrphanLayouts();       // Layouts that never mapped to a Window
        }

        static void BucketLayoutForIfaceAndHandle_NoLock(const void* ifaceOrHandle,
                                                 fox::ui::Layout* layout)
        {
            if (!ifaceOrHandle || !layout)
                return;

            auto* iface  = reinterpret_cast<const fox::ui::WindowInterface*>(ifaceOrHandle);
            auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(const_cast<void*>(ifaceOrHandle));

            auto pushUnique = [layout](auto& vec)
            {
                if (std::find(vec.begin(), vec.end(), layout) == vec.end())
                    vec.push_back(layout);
            };

            // Track under both the interface view and the handle view
            pushUnique(g_ifaceLayouts[iface]);
            pushUnique(g_handleLayouts[handle]);

            // If we already know which window this handle belongs to, bind immediately.
            auto itWin = g_handleToWindow.find(handle);
            if (itWin != g_handleToWindow.end() && itWin->second)
            {
                BindHandleLayoutsToWindow_NoLock(handle, itWin->second);
            }
        }

        static void AttachRootLayoutForWindow_NoLock(fox::ui::Window* w, const char* reason)
        {
            if (!w)
                return;

            auto* root = GetWindowRootLayout(w); // window + 0x28
            if (!root)
                return;

            // Only adopt if we already know this pointer as a Layout
            if (g_seenLayoutsSet.find(root) == g_seenLayoutsSet.end())
            {
                spdlog::debug("[ROOT LAYOUT SKIP] window={} rawRoot={} reason={}",
                              static_cast<const void*>(w),
                              static_cast<const void*>(root),
                              reason ? reason : "");
                return;
            }

            // Make sure it's tracked & owned
            TrackLayout_NoLock(root);
            SetLayoutOwner_NoLock(root, w, reason ? reason : "RootLayout");
        }

        // ---------------------------------------------------------------------
        // Hooks
        // ---------------------------------------------------------------------

        // text hooks
        void __fastcall SetTextForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, const char* rawText,
                                                    bool isLocalized)
        {
            if (rawText)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeTextByPtr[reinterpret_cast<fox::ui::ModelNode*>(nodeText)] = rawText;
            }

            spdlog::debug("[STFMNT] uix={} nodeText={} textUnit={} rawText={} isLocalized={}",
                          uix, nodeText, textUnit, rawText ? rawText : "", isLocalized);

            SetTextForModelNodeText(uix, nodeText, textUnit, rawText, isLocalized);
        }

        void __fastcall SetTextForModelNodeTextInternalHook(void* nodeText, void* textUnit, const char* rawText,
                                                            bool isLocalized)
        {
            if (rawText)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeTextByPtr[reinterpret_cast<fox::ui::ModelNode*>(nodeText)] = rawText;
            }

            spdlog::debug("[STFMNTI] nodeText={} textUnit={} rawText={} isLocalized={}", nodeText, textUnit,
                          rawText, isLocalized);
            SetTextForModelNodeTextInternal(nodeText, textUnit, rawText, isLocalized); // original
        }

        void __fastcall SetTextUnitsForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, uint64_t stringId)
        {
            const char* resolved = nullptr;
            if (uix && stringId)
            {
                resolved = GetManagerText(uix, static_cast<fox::StrCode32>(stringId));
                if (resolved)
                {
                    std::lock_guard<std::mutex> lock(g_uiMutex);
                    g_nodeTextByPtr[reinterpret_cast<fox::ui::ModelNode*>(nodeText)] = resolved;
                }
            }

            spdlog::debug("[STUFMNT] uix={} nodeText={} textUnit={} stringId={} text={}",
                          uix,
                          static_cast<const void*>(nodeText),
                          textUnit,
                          stringId,
                          resolved ? resolved : "");

            SetTextUnitsForModelNodeText(uix, nodeText, textUnit, stringId);
        }

        bool __fastcall SetTextUnitsHook(void* nodeText, void* textUnit, uint64_t stringId)
        {
            bool ok = SetTextUnits(nodeText, textUnit, stringId);
            spdlog::debug("[STU] retBool={} nodeText={} textUnit={} stringId={}", ok, nodeText, textUnit, stringId);
            return ok;
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
            spdlog::debug("[NCS] owner={} parentComp={} portPtr={} childArg={}",
                          owner, parentComp, portPtr, childArg);

            return NodeConnectShim(owner, parentComp, portPtr, childArg);
        }

        fox::ui::Layout* __fastcall LayoutGetLayoutHook(fox::ui::Layout* self, int layoutId)
        {
            auto retLayout = LayoutGetLayout(self, layoutId);

            if (retLayout)
            {
                TrackLayout(retLayout);

                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto itW = g_layoutToWindow.find(self);
                if (itW != g_layoutToWindow.end() && itW->second)
                {
                    SetLayoutOwner_NoLock(retLayout, itW->second, "LayoutGetLayout");
                }
            }

            spdlog::info("[LayoutGetLayout] retLayout={} self={} layoutId={}",
                         static_cast<const void*>(retLayout),
                         static_cast<const void*>(self),
                         layoutId);

            return retLayout;
        }

        // This function is shared between multiple components and it simply returns self + 0x28 TODO: Generic rename
        fox::ui::Layout* __fastcall GetWindowInterfaceLayoutHook(fox::ui::WindowInterface* self)
        {
            auto* layout = GetWindowInterfaceLayout(self); // original (self + 0x28 helper)
            if (!self || !layout)
                return layout;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // In this function, `self` is a WindowInterface* (or handle),
                // NOT a fox::ui::Window*, so comparing its vtbl to g_WindowVtbl is wrong.

                fox::ui::Window* w = nullptr;

                // First, assume it's actually a WindowHandle-based interface
                auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(self);
                auto itH = g_handleToWindow.find(handle);
                if (itH != g_handleToWindow.end())
                    w = itH->second;

                // Fallback: sometimes a Window* is passed directly as the interface
                if (!w)
                {
                    auto* asWindow = reinterpret_cast<fox::ui::Window*>(self);
                    auto itW = g_windows.find(asWindow);
                    if (itW != g_windows.end())
                        w = itW->second.window;
                }

                if (w)
                {
                    // Optionally track, then bind
                    TrackLayout_NoLock(layout);
                    SetLayoutOwner_NoLock(layout, w, "GetWindowInterfaceLayout");
                }
            }

            spdlog::debug("[GetWindowInterfaceLayout] self={} layout={}",
                          static_cast<const void*>(self),
                          static_cast<const void*>(layout));

            return layout;
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
            spdlog::debug("[GetModelNodeCommonInternalHook] GetModelNodeCommonInternal model={} sid32=#{:08X}",
                          selfModel, (uint32_t)sid);
            return GetModelNodeCommonInternal(selfModel, sid);
        }

        bool __fastcall IsHaveModelNodeCommonHook(void* selfUixUtility, const void* model, fox::StrCode stringId)
        {
            spdlog::debug("[IsHaveModelNodeCommonHook] IsHaveModelNodeCommon model={} sid32=#{:08X}",
                          model, stringId);
            return IsHaveModelNodeCommon(selfUixUtility, model, stringId);
        }

        // lifecycle
        void __fastcall OnLayoutComponentDestroyHook(void* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_componentToLayout.erase(reinterpret_cast<fox::ui::LayoutComponent*>(self));
            }

            OnLayoutComponentDestroy(self);
        }

        // Creation ctx harvest
        void* __fastcall NewUiModelTextHook(uint32_t sceneStr, void* creationCtx, void* a2, void* a3)
        {
            auto ret = NewUiModelText(sceneStr, creationCtx, a2, a3);
            spdlog::debug("[NewUiModelText] node={} sceneStr=#{:08X} ctx={}", ret, sceneStr, creationCtx);

            return ret;
        }

        fox::SharedPtr<fox::ui::Model>* __fastcall NewUiModelSharedPtrHook(
            fox::SharedPtr<fox::ui::Model>* outPtr, fox::FilePtr* file, fox::StrCode32 name, uint64_t unused_or_flags)
        {
            auto ret = NewUiModelSharedPtr(outPtr, file, name, unused_or_flags);

            fox::ui::Model* model = outPtr ? outPtr->Object : nullptr;
            if (model)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto& info = g_modelInfo[model];
                info.modelName = name;
            }

            spdlog::info("[NewUiModelSharedPtr] model={} file={} name=#{:08X} flags={}",
                         static_cast<void*>(model),
                         static_cast<void*>(file),
                         static_cast<uint32_t>(name),
                         unused_or_flags);
            return ret;
        }

        fox::SharedPtr<fox::ui::Layout>* __fastcall NewUiLayoutSharedPtrHook(
            fox::SharedPtr<fox::ui::Layout>* outPtr, uint32_t flags)
        {
            auto ret = NewUiLayoutSharedPtr(outPtr, flags);

            fox::ui::Layout* layout = (outPtr ? outPtr->Object : nullptr);
            if (layout)
            {
                TrackLayout(layout);
                spdlog::debug("[NewUiLayoutSharedPtr] layout={} flags={}",
                              static_cast<const void*>(layout),
                              flags);
            }

            return ret;
        }

        fox::ui::ModelNode* __fastcall UiModelNodeCtorHook(fox::ui::ModelNode* self, fox::StrCode32 name)
        {
            auto ret = UiModelNodeCtor(self, name);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeNameByPtr[self] = name;
            }
            spdlog::info("[UiModelNodeCtor] node={} name=#{:08X}",
                         static_cast<void*>(self),
                         static_cast<uint32_t>(name));

            return ret;
        }

        fox::ui::Layout* __fastcall LayoutCtorHook(fox::ui::Layout* self, uint32_t layoutFlags)
        {
            auto ret = LayoutCtor(self, layoutFlags);
            spdlog::debug("[LayoutCtor] ret={} self={} flags={}",
                          static_cast<void*>(ret),
                          static_cast<void*>(self),
                          layoutFlags);

            return ret;
        }

        fox::ui::Model* __fastcall ModelCtorHook(fox::ui::Model* self, fox::FilePtr* file, fox::StrCode32 name)
        {
            auto ret = ModelCtor(self, file, name);
            spdlog::debug("[ModelCtor] ret={} self={} file={} name={}",
                          static_cast<void*>(ret),
                          static_cast<void*>(self),
                          static_cast<void*>(file),
                          name);

            return ret;
        }

        void __fastcall LayoutDtorHook(fox::ui::Layout* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // 1) Remove from global layout tracking
                {
                    auto it = g_seenLayoutsSet.find(self);
                    if (it != g_seenLayoutsSet.end())
                        g_seenLayoutsSet.erase(it);

                    auto itV = std::remove(g_seenLayouts.begin(), g_seenLayouts.end(), self);
                    if (itV != g_seenLayouts.end())
                        g_seenLayouts.erase(itV, g_seenLayouts.end());
                }

                // 2) Remove from layout -> window map
                g_layoutToWindow.erase(self);

                // 3) Remove from every WindowInfo.layouts
                for (auto& kv : g_windows)
                {
                    auto& lv = kv.second.layouts;
                    auto itL = std::remove(lv.begin(), lv.end(), self);
                    if (itL != lv.end())
                        lv.erase(itL, lv.end());
                }

                // 4) Remove from handle -> layouts buckets
                for (auto& kv : g_handleLayouts)
                {
                    auto& vec = kv.second;
                    auto itL  = std::remove(vec.begin(), vec.end(), self);
                    if (itL != vec.end())
                        vec.erase(itL, vec.end());
                }

                // 5) Remove from iface -> layouts buckets
                for (auto& kv : g_ifaceLayouts)
                {
                    auto& vec = kv.second;
                    auto itL  = std::remove(vec.begin(), vec.end(), self);
                    if (itL != vec.end())
                        vec.erase(itL, vec.end());
                }
            }

            LayoutDtor(self);
            spdlog::debug("[LayoutDtor] self={}", static_cast<void*>(self));
        }

        void __fastcall ModelDtorHook(fox::ui::Model* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_modelInfo.erase(self); // model -> info
            }
            ModelDtor(self);
            spdlog::debug("[ModelDtor] self={}", static_cast<void*>(self));
        }

        void __fastcall ModelNodeDtorHook(fox::ui::ModelNode* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeNameByPtr.erase(self); // node -> name32
                g_nodeTextByPtr.erase(self); // node -> text
            }

            ModelNodeDtor(self);
            spdlog::debug("[ModelNodeDtor] self={}", static_cast<void*>(self));
        }

        // window plumbing hooks
        void __fastcall UpdateWindowGraphHook(void* selfWindow)
        {
            UpdateWindowGraph(selfWindow);
        }

        void __fastcall AddChildWindowHook(fox::ui::Window* selfWindow, fox::ui::Window* childWindow)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto& parentInfo = g_windows[selfWindow];
                parentInfo.window = selfWindow;

                // dedupe children
                auto& children = parentInfo.children;
                if (std::find(children.begin(), children.end(), childWindow) == children.end())
                {
                    children.push_back(childWindow);
                }

                auto& childInfo = g_windows[childWindow];
                childInfo.window = childWindow;
                childInfo.parentWindow = selfWindow;
            }

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
                std::lock_guard<std::mutex> lock(g_uiMutex);

                fox::ui::Window* w = nullptr;

                // windowFunction is the same "resourceCreator" you stored in WindowCtorHook
                auto it = g_windowFuncToWindow.find(windowFunction);
                if (it != g_windowFuncToWindow.end())
                    w = it->second;

                if (w)
                {
                    auto* layout = reinterpret_cast<fox::ui::Layout*>(L);
                    SetLayoutOwner_NoLock(layout, w, "GetWindowLayout");
                }
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

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                fox::ui::Window* w = nullptr;

                auto it = g_windowFuncToWindow.find(windowFunction);
                if (it != g_windowFuncToWindow.end())
                    w = it->second;
                else
                {
                    auto* asWindow = reinterpret_cast<fox::ui::Window*>(windowFunction);
                    auto it2 = g_windows.find(asWindow);
                    if (it2 != g_windows.end())
                        w = it2->second.window;
                }

                auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(h);

                if (w && handle)
                {
                    g_handleToWindow[handle] = w;

                    auto& info = g_windows[w];
                    info.window       = w;
                    info.windowHandle = handle;

                    spdlog::info("[WIN HANDLE] handle={} window={}",
                                 static_cast<const void*>(handle),
                                 static_cast<const void*>(w));

                    // NEW: root layout opportunistic bind
                    AttachRootLayoutForWindow_NoLock(w, "GetWindowHandle_root");

                    BindHandleLayoutsToWindow_NoLock(handle, w);
                }
            }

            return h;
        }

        fox::String* __fastcall GetWindowNameHook(fox::ui::Window* self)
        {
            auto name = GetWindowName(self);

            return name;
        }
        
        fox::ui::Window* __fastcall WindowCtorHook(fox::ui::Window* self,
                                                   fox::ui::WindowFunction* resourceCreator,
                                                   fox::String* name,
                                                   uint32_t type,
                                                   fox::ui::WindowResourceCreator** creatorIface,
                                                   uint16_t zOrder,
                                                   uint32_t groupId,
                                                   uint32_t updateMask)
        {
            auto window = WindowCtor(self, resourceCreator, name, type, creatorIface, zOrder, groupId, updateMask);

            uint64_t hash = name ? name->hash : 0;
            std::string nameStr;
            if (name && hash != 0)
                nameStr = FoxStringToStd(name);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto& info = g_windows[window];
                info.window         = window;
                info.windowFunction = resourceCreator;
                if (!nameStr.empty())
                    info.windowName = nameStr;

                g_windowFuncToWindow[resourceCreator] = window;

                // NEW: root layout opportunistic bind
                AttachRootLayoutForWindow_NoLock(window, "WindowCtor_root");
            }

            spdlog::info(
                "[WIN CTOR] retWin={} self={} resourceCreator={} name=\"{}\" hash=#{:016X} type={} creatorIface={} zOrder={} groupId={} updateMask={}",
                static_cast<void*>(window),
                static_cast<void*>(self),
                static_cast<void*>(resourceCreator),
                nameStr,
                hash,
                type,
                static_cast<void*>(creatorIface),
                zOrder,
                groupId,
                updateMask);

            return window;
        }

        void __fastcall WindowDtorHook(fox::ui::Window* self)
        {
            spdlog::debug("[WIN DTOR] self={}", static_cast<void*>(self));
            WindowDtor(self);
        }

        void __fastcall ProcessWindowHook(fox::ui::Window* self,
                                          const uint32_t* msg,
                                          const uint64_t* arg0,
                                          const uint64_t* arg1)
        {
            spdlog::debug("[PROCESS WIN] self={} msg={} arg0={} arg1={}",
                          static_cast<void*>(self),
                          static_cast<const void*>(msg),
                          static_cast<const void*>(arg0),
                          static_cast<const void*>(arg1));
            ProcessWindow(self, msg, arg0, arg1);
        }

        fox::ui::Window* __fastcall FindChildWindowHook(const fox::ui::Window* self, fox::StrCode32 id)
        {
            auto childWin = FindChildWindow(self, id);
            spdlog::debug("[FIND CHILD WIN] retWin={} self={} id={}",
                          static_cast<void*>(childWin),
                          static_cast<const void*>(self),
                          id);
            return childWin;
        }

        fox::ui::Window* __fastcall FindUiWindowHook(fox::StrCode32 id)
        {
            auto retWin = FindUiWindow(id);
            spdlog::debug("[FIND WIN] retWin={} id={}",
                          static_cast<void*>(retWin),
                          id);
            return retWin;
        }

        void __fastcall UpdateWindowLayoutsHook(fox::ui::WindowManager* self, fox::StrCode32 groupId)
        {
            spdlog::debug("[UPDATE WINDOW LAYOUT] sekf={} id={}",
                          static_cast<void*>(self),
                          groupId);
            UpdateWindowLayouts(self, groupId);
        }

 void __fastcall SetLayoutInfoHook(void* windowHandle, const void* layoutInfo)
        {
            // Call the real thing first to keep engine semantics intact
            SetLayoutInfo(windowHandle, layoutInfo);

            fox::ui::Window* w = nullptr;
            std::vector<fox::ui::Layout*> layouts;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(windowHandle);

                // Resolve handle -> window if we already know it
                auto itWin = g_handleToWindow.find(handle);
                if (itWin != g_handleToWindow.end())
                    w = itWin->second;

                // Find any Layout* embedded in layoutInfo that are already tracked
                layouts = ScanLayoutInfoForLayouts_NoLock(layoutInfo);

                // Bucket layouts under this handle for later binding if window not known yet
                if (handle && !layouts.empty())
                {
                    auto& bucket = g_handleLayouts[handle];
                    for (auto* L : layouts)
                    {
                        if (!L)
                            continue;
                        if (std::find(bucket.begin(), bucket.end(), L) == bucket.end())
                            bucket.push_back(L);
                    }
                }

                // If we already know the window, immediately mark ownership
                if (w && !layouts.empty())
                {
                    for (auto* L : layouts)
                    {
                        if (!L)
                            continue;
                        SetLayoutOwner_NoLock(L, w, "SetLayoutInfo_scan");
                    }
                }
            }

            spdlog::info(
                "[SetLayoutInfo] handle={} layoutInfo={} window={} layoutsCount={} firstLayout={}",
                windowHandle,
                layoutInfo,
                static_cast<const void*>(w),
                layouts.size(),
                layouts.empty() ? nullptr : static_cast<const void*>(layouts[0]));
        }

        void* __fastcall GetTextUnitsHook(int index)
        {
            void* tu = GetTextUnits(index); // original
            spdlog::debug("[GET TU] index={} -> {}", index, tu);
            return tu;
        }

        void* __fastcall GetTextUnitsInternalHook(void* fontMgr, int index)
        {
            void* tu = GetTextUnitsInternal(fontMgr, index); // original
            spdlog::debug("[GET TUI] fontMgr={} index={} -> {}", fontMgr, index, tu);
            return tu;
        }

        void __fastcall SetTextUnitHook(void* selfTextUnit, char* text, uint32_t flags, uint16_t p3, uint16_t p4,
                                        float size, float tracking, uint32_t p7, uint32_t p8)
        {
            SetTextUnit(selfTextUnit, text, flags, p3, p4, size, tracking, p7, p8);
            spdlog::debug("[SET TU] selfTextUnit={} text={} flags={} p3={} p4={} size={} tracking={} p7={} p8={}",
                          selfTextUnit, text, flags, p3, p4, size, tracking, p7, p8);
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
            // spdlog::info("[GRAPH UPDATE] selfGraph={}", selfGraph);

            GraphUpdate(selfGraph);
        }

        fox::ui::Layout* __fastcall GetUixLayoutHook(void* manager, const fox::ui::WindowInterface* windowIface, fox::StrCode layoutId)
        {
            auto* layout = GetUixLayout(manager, windowIface, layoutId);
            if (!layout)
                return nullptr;

            TrackLayout(layout);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                BucketLayoutForIfaceAndHandle_NoLock(windowIface, layout);
            }

            spdlog::info("[GetUixLayout] mgr={} iface={} layoutId=#{:08X} layout={}",
                         manager, windowIface, (uint32_t)layoutId, layout);

            return layout;
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
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto it = g_componentToLayout.find(parentComp);
                if (it != g_componentToLayout.end())
                {
                    g_componentToLayout[childComp] = it->second;
                }
            }

            spdlog::debug("[CLC] childComp={} parentComp={} portPtr={}",
                          childComp, parentComp, portPtr);
            ConnectLayoutComponent(childComp, parentComp, portPtr);
        }

        void __fastcall ConnectLayoutUtilityComponentHook(void* childComp, void* parentComp, fox::StrCode portSid)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto it = g_componentToLayout.find(parentComp);
                if (it != g_componentToLayout.end())
                {
                    g_componentToLayout[childComp] = it->second;
                }
            }

            spdlog::debug("[CLU] childComp={} parentComp={} portSid=#{:08X}",
                          childComp, parentComp, portSid);

            ConnectLayoutUtilityComponent(childComp, parentComp, portSid);
        }

        bool __fastcall CreateChildWindowsHook(void* creator, fox::ui::Window* parentWin)
        {
            bool ok = CreateChildWindows(creator, parentWin);

            return ok;
        }

        void __fastcall ConnectChildWindowToNodeHook(fox::ui::Window* parentWin, fox::ui::WindowHandle* childHandle, fox::ui::LayoutComponent* parentComp, void* portPtr)
        {
            fox::ui::Layout* layout   = nullptr;
            fox::ui::Window* childWin = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // Resolve child from handle
                auto itChild = g_handleToWindow.find(childHandle);
                if (itChild != g_handleToWindow.end())
                    childWin = itChild->second;
                else
                    childWin = reinterpret_cast<fox::ui::Window*>(childHandle);

                // Resolve layout for this LayoutComponent
                auto itLayout = g_componentToLayout.find(parentComp);
                if (itLayout != g_componentToLayout.end())
                {
                    layout = itLayout->second;

                    // Parent owns this layout
                    if (parentWin && layout)
                        SetLayoutOwner_NoLock(layout, parentWin, "ConnectChildWindowToNode");
                }

                if (childWin)
                {
                    auto& childInfo = g_windows[childWin];
                    childInfo.window       = childWin;
                    childInfo.parentWindow = parentWin;
                    childInfo.attachLayout = layout;
                    childInfo.attachAnchor = portPtr;

                    if (parentWin)
                    {
                        auto& parentInfo = g_windows[parentWin];
                        parentInfo.window = parentWin;

                        auto& children = parentInfo.children;
                        if (std::find(children.begin(), children.end(), childWin) == children.end())
                            children.push_back(childWin);
                    }
                }
            }

            spdlog::debug(
                "[ANCHOR] parentWin={} childHandle={} parentComp={} portPtr={} layout={} childWin={}",
                static_cast<const void*>(parentWin),
                static_cast<const void*>(childHandle),
                static_cast<const void*>(parentComp),
                portPtr,
                static_cast<const void*>(layout),
                static_cast<void*>(childWin));

            ConnectChildWindowToNode(parentWin, childHandle, parentComp, portPtr);
        }

        void __fastcall ConnectChildWindowToRootHook(fox::ui::Window* parentWin, fox::ui::WindowHandle* childHandle)
        {
            fox::ui::Window* childWin = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto it = g_handleToWindow.find(childHandle);
                if (it != g_handleToWindow.end())
                    childWin = it->second;
                else
                    childWin = reinterpret_cast<fox::ui::Window*>(childHandle);

                if (childWin)
                {
                    auto& childInfo = g_windows[childWin];
                    childInfo.window       = childWin;
                    childInfo.parentWindow = parentWin;
                    childInfo.windowHandle = childHandle;

                    auto& parentInfo = g_windows[parentWin];
                    parentInfo.window = parentWin;

                    auto& children = parentInfo.children;
                    if (std::find(children.begin(), children.end(), childWin) == children.end())
                        children.push_back(childWin);

                    g_handleToWindow[childHandle] = childWin;

                    spdlog::info("[ROOT HANDLE] parentWin={} childHandle={} childWin={}",
                                 static_cast<const void*>(parentWin),
                                 static_cast<const void*>(childHandle),
                                 static_cast<const void*>(childWin));

                    // NEW: root layout bind on both parent and child
                    AttachRootLayoutForWindow_NoLock(parentWin, "ConnectChildWindowToRoot_parent");
                    AttachRootLayoutForWindow_NoLock(childWin,  "ConnectChildWindowToRoot_child");

                    BindHandleLayoutsToWindow_NoLock(childHandle, childWin);
                }
                else
                {
                    spdlog::info("[ROOT HANDLE] parentWin={} childHandle={} (no childWin)",
                                 static_cast<const void*>(parentWin),
                                 static_cast<const void*>(childHandle));
                }
            }

            ConnectChildWindowToRoot(parentWin, childHandle);
        }

        void* __fastcall GetConnectModelHook(void* self /*ModelNodeConnection**/, void* outTransform /*=nullptr*/)
        {
            auto ret = GetConnectModel(self, outTransform);
            spdlog::debug("[GetConnectModel] model={} self={} outTransform={}", ret, self, outTransform);
            return ret;
        }

        void __fastcall ConnectWindowToParentHook(void* windowFunction, void* parentComp, void* portPtr)
        {
            fox::ui::Window* ownerWindow = nullptr;
            fox::ui::Layout* layout      = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // WindowFunction* -> Window* (original assumption)
                auto itWin = g_windowFuncToWindow.find(windowFunction);
                if (itWin != g_windowFuncToWindow.end())
                    ownerWindow = itWin->second;

                // Fallback: maybe windowFunction is actually a Window*
                if (!ownerWindow)
                {
                    auto* asWindow = reinterpret_cast<fox::ui::Window*>(windowFunction);
                    auto itW2 = g_windows.find(asWindow);
                    if (itW2 != g_windows.end())
                        ownerWindow = itW2->second.window;
                }

                // LayoutComponent* -> Layout*
                auto itLayout = g_componentToLayout.find(
                    reinterpret_cast<fox::ui::LayoutComponent*>(parentComp));
                if (itLayout != g_componentToLayout.end())
                    layout = itLayout->second;

                if (ownerWindow && layout)
                {
                    SetLayoutOwner_NoLock(layout, ownerWindow, "ConnectWindowToParent");
                }
            }

            spdlog::info("[CWP] windowFunc={} parentComp={} portPtr={} window={} layout={}",
                         windowFunction,
                         parentComp,
                         portPtr,
                         static_cast<const void*>(ownerWindow),
                         static_cast<const void*>(layout));

            ConnectWindowToParent(windowFunction, parentComp, portPtr);
        }

        void __fastcall SetModelNodeTextDisplayWidthHook(void* nodeText, float width)
        {
            spdlog::debug("[SetModelNodeTextDisplayWidth] nodeText={} width={}", nodeText, width);
            SetModelNodeTextDisplayWidth(nodeText, width);
        }

        void __fastcall SetModelNodeTextDisplayHeightHook(void* nodeText, float height)
        {
            spdlog::debug("[SetModelNodeTextDisplayHeight] nodeText={} width={}", nodeText, height);
            SetModelNodeTextDisplayHeight(nodeText, height);
        }

        void __fastcall SetUixModelNodeTextFontSizeHook(void* uix, void* nodeText, float px, float secondary)
        {
            spdlog::debug("[SetUixModelNodeTextFontSize] uix={} modelNodeText={} px={} secondary={}", uix, nodeText, px,
                          secondary);
            SetUixModelNodeTextFontSize(uix, nodeText, px, secondary);
        }

        void __fastcall SetModelNodeTextFontSizeHook(void* nodeText, float px, float secondary)
        {
            spdlog::debug("[SetModelNodeTextFontSize] modelNodeText={} px={} secondary={}", nodeText, px, secondary);
            SetModelNodeTextFontSize(nodeText, px, secondary);
        }

        void __fastcall SetModelNodeTextFontSpaceHook(void* nodeText, float px, float secondary)
        {
            spdlog::debug("[SetModelNodeTextFontSpace] modelNodeText={} px={} secondary={}", nodeText, px, secondary);
            SetModelNodeTextFontSpace(nodeText, px, secondary);
        }

        void __fastcall SetModelNodeTextColorRGBHook(void* uix, void* nodeText, float r, float g, float b)
        {
            spdlog::debug("[SetModelNodeTextColorRGB] uix={} nodeText={} r={} g={} b={}", uix, nodeText, r, g, b);
            SetModelNodeTextColorRGB(uix, nodeText, r, g, b);
        }

        void __fastcall ResetModelNodeTextFontSizeHook(void* nodeText)
        {
            spdlog::debug("[ResetModelNodeTextFontSize] nodeText={}", nodeText);
            ResetModelNodeTextFontSize(nodeText);
        }

        void __fastcall ResetModelNodeTextFontSpaceHook(void* nodeText)
        {
            spdlog::debug("[ResetModelNodeTextFontSpace] nodeText={}", nodeText);
            ResetModelNodeTextFontSpace(nodeText);
        }

        bool __fastcall GetModelNodeWorldVisibilityHook(const void* node)
        {
            return GetModelNodeWorldVisibility(node);
        }

        void __fastcall BuildTextAreaPackHook(void* modelNodeText, TextAreaPack* out)
        {
            BuildTextAreaPack(modelNodeText, out);
        }

        void __fastcall ApplyTextAndMeasureHook(void* act, void* node, void* unitsCtx, void* fmtCtx)
        {
            ApplyTextAndMeasure(act, node, unitsCtx, fmtCtx);
        }

        void __fastcall RunAnalysisHook(ActSetText* self)
        {
            RunAnalysis(self);
        }

        void __fastcall SetModelNodeTextDisplayAreaWidthOffsetHook(void* nodeText, float addWidth, float addOffset)
        {
            SetModelNodeTextDisplayAreaWidthOffset(nodeText, addWidth, addOffset);
        }

        void __fastcall LayoutConnectHook(void* uiUtil, fox::ui::WindowHandle* windowIface,
                                  fox::StrCode sidA, fox::StrCode sidB,
                                  fox::StrCode sidModel, fox::StrCode sidPort)
        {
            // First, let the engine wire everything
            LayoutConnect(uiUtil, windowIface, sidA, sidB, sidModel, sidPort);

            if (!windowIface)
                return;

            // Root layout under this interface
            auto* rootLayout =
                GetUixLayout(uiUtil, windowIface, sidA); // same 'this', same iface, sidA as the id
            if (!rootLayout)
                return;

            int idB = static_cast<int>(static_cast<uint32_t>(sidB));
            fox::ui::Layout* layoutB = LayoutGetLayout(rootLayout, idB);

            TrackLayout(rootLayout);
            if (layoutB) TrackLayout(layoutB);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                BucketLayoutForIfaceAndHandle_NoLock(windowIface, rootLayout);
                BucketLayoutForIfaceAndHandle_NoLock(windowIface, layoutB);
            }

            spdlog::info(
                "[LayoutConnect] uiUtil={} iface={} sidA=#{:08X} sidB=#{:08X} sidModel=#{:08X} sidPort=#{:08X} root={} B={}",
                uiUtil,
                windowIface,
                (uint32_t)sidA,
                (uint32_t)sidB,
                (uint32_t)sidModel,
                (uint32_t)sidPort,
                static_cast<const void*>(rootLayout),
                static_cast<const void*>(layoutB));
        }


        fox::ui::Window* __fastcall WindowCreateHook(const fox::ui::WindowResourceCreator* rc,
                                                     const fox::String* name, uint32_t flags,
                                                     fox::ui::Window* parent,
                                                     uint16_t zOrder,
                                                     uint32_t opt6,
                                                     uint32_t opt7)
        {
            auto w = WindowCreate(rc, name, flags, parent, zOrder, opt6, opt7);

            uint64_t hash = name ? name->hash : 0;
            std::string nameStr;
            if (name && hash != 0)
                nameStr = FoxStringToStd(name);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto& info          = g_windows[w];
                info.window         = w;
                info.parentWindow   = parent;
                info.windowFunction = const_cast<fox::ui::WindowResourceCreator*>(rc);
                if (!nameStr.empty())
                    info.windowName = nameStr;

                // NEW: root layout opportunistic bind
                AttachRootLayoutForWindow_NoLock(w, "WindowCreate_root");
            }

            spdlog::info("[WINDOW CREATE] window={} parent={} name=\"{}\" hash=#{:016X} len={}",
                         static_cast<void*>(w),
                         static_cast<void*>(parent),
                         nameStr,
                         hash,
                         name ? static_cast<unsigned long long>(name->length) : 0ull);

            return w;
        }

        void __fastcall RegisterUiGraphNodeCtorHook(fox::StrCode32 sig32, fox::UiGraphNodeCtorFn ctor)
        {
            RegisterUiGraphNodeCtor(sig32, ctor);
            spdlog::debug("[REG UI GRAPH NODE] sig32=#{:08X} ctorThunk={}",
                          sig32,
                          static_cast<const void*>(reinterpret_cast<const void*>(ctor)));
        }

        void __fastcall GraphNodeFactoryHook(fox::UiShared* outGraphNode, fox::StrCode32 graphSid)
        {
            GraphNodeFactory(outGraphNode, graphSid);
            // spdlog::debug("[UI GRAPH NODE FACTORY] outGraphNode={} graphSid=#{:08X}",
            //               static_cast<const void*>(outGraphNode),
            //               graphSid);
        }

        fox::StrCode32* __fastcall GetStringIdHook(fox::StrCode* out, const char* string)
        {
            fox::StrCode32* sid = GetStringId(out, string);

            spdlog::debug("[STRING ID] retSid={} out={} string={}", *sid, *out, string);

            return sid;
        }

        void __fastcall CallHudMessageHook(void* commonDataManager, uint32_t msgId)
        {
            spdlog::debug("[CALL HUD MSG] commonDataManager={} msgId={}", commonDataManager, msgId);

            CallHudMessage(commonDataManager, msgId);
        }

        void __fastcall CallHudMessageWithNumberHook(void* commonDataManager /*RCX*/, uint32_t msgId /*EDX*/,
                                                     uint32_t num1 /*R8D*/, uint32_t num2 /*R9D*/)
        {
            spdlog::debug("[CALL HUD NMR] commonDataManager={} msgId={} num1={} num2={}", commonDataManager, msgId,
                          num1, num2);

            CallHudMessageWithNumber(commonDataManager, msgId, num1, num2);
        }

        void __fastcall CallHudMessageWithReceiverHook(void* commonDataManager /*RCX*/, uint32_t msgId /*EDX*/,
                                                       const void* messageArgs /*R8*/,
                                                       uint32_t receiverStrCode32 /*R9D*/)
        {
            spdlog::debug("[CALL HUD RCVR] commonDataManager={} msgId={} messageArgs={} receiverStrCode32={}",
                          commonDataManager, msgId, messageArgs, receiverStrCode32);

            CallHudMessageWithReceiver(commonDataManager, msgId, messageArgs, receiverStrCode32);
        }

        void __fastcall HudCommonCallHudMessageHook(void* hudSystemImpl /*RCX*/, uint32_t msgId /*EDX*/,
                                                    uint32_t arg /*R8D*/, uint32_t receiverStrCode32 /*R9D*/)
        {
            spdlog::debug("[HUD COMMON CALL HUD MSG] hudSystemImpl={} msgId={} arg={} receiverStrCode32={}",
                          hudSystemImpl, msgId, arg, receiverStrCode32);

            HudCommonCallHudMessage(hudSystemImpl, msgId, arg, receiverStrCode32);
        }

        void __fastcall InitializeHudUigDatasHook(void* self)
        {
            spdlog::debug("[INIT HUD UIG] self={}", self);

            InitializeHudUigDatas(self);
        }

        bool __fastcall AnnounceLogViewHook(void* cdm, // RCX: tpp::ui::hud::CommonDataManager*
                                            const char* text, // RDX: zero-terminated message
                                            uint8_t flags, // R8B : bitfield (uses both BL and BPL; 0x10 tested)
                                            uint8_t opts // R9B : aux/route selector
        )
        {
            bool ret = AnnounceLogView(cdm, text, flags, opts);
            spdlog::debug("[ANNC LOG] ret={} cdm={} text={} flags={} opts={}",
                          ret, cdm, text ? text : "", flags, opts);
            return ret;
        }

        void __fastcall SetLayoutActiveHook(void* windowIface, bool enable)
        {
            spdlog::debug("[SLA] windowIface={} enable={}", windowIface, enable);

            return SetLayoutActive(windowIface, enable);
        }

        void __fastcall SetUiModelNodeTranslateHook(void* node, const float* v)
        {
            spdlog::debug("[SET TRANSLATE] node={} v=({}, {}, {}, {})",
                          node, v[0], v[1], v[2], v[3]);

            SetUiModelNodeTranslate(node, v);
        }

        void* __fastcall GetLayoutComponentHook(void* self)
        {
            auto retComponent = GetLayoutComponent(self);
            spdlog::debug("[GetLayoutComponent] self={} ret={}", self, retComponent);
            return retComponent;
        }

        void __fastcall SetupModelHook(void* self)
        {
            SetupModel(self);
            spdlog::debug("[SETUP MODEL] self={}", self);
        }

        bool __fastcall ReadUiModelFileHook(fox::ui::Model* model)
        {
            bool ok = ReadUiModelFile(model);

            void* fileHeader = nullptr;
            if (model)
                fileHeader = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(model) + 0x68);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto& info = g_modelInfo[model];
                info.fileHeader = fileHeader;
                // info.modelName is filled in NewUiModelSharedPtrHook
            }

            spdlog::info("[READ MODEL FILE] ok={} model={} fileHeader={}",
                         ok,
                         static_cast<void*>(model),
                         fileHeader);
            return ok;
        }

        void __fastcall ReadUiModelNodeHook(fox::ui::ModelNode* self,
                                            fox::ui::ModelFileHeader* fileHeader,
                                            fox::ui::ModelNodeHeader* nodeHeader,
                                            fox::StrCode32* strCode32s,
                                            uint32_t* outName)
        {
            ReadUiModelNode(self, fileHeader, nodeHeader, strCode32s, outName);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // Find model whose fileHeader matches this one
                for (auto& kv : g_modelInfo)
                {
                    fox::ui::Model* model = kv.first;
                    auto& info = kv.second;

                    if (info.fileHeader == fileHeader)
                    {
                        info.nodes.push_back(self);
                        break; // assume first hit is fine
                    }
                }
            }

            spdlog::debug("[READ MODEL NODE] self={} fileHeader={} nodeHeader={} strCode32s={} outName={}",
                          static_cast<void*>(self),
                          static_cast<void*>(fileHeader),
                          static_cast<void*>(nodeHeader),
                          reinterpret_cast<const void*>(strCode32s),
                          reinterpret_cast<const void*>(outName));
        }

        const char* __fastcall GetManagerTextHook(void* self, fox::StrCode32 sid32)
        {
            auto ret = GetManagerText(self, sid32); // original
            spdlog::debug("[GET MANAGER TEXT] ret={} self={} sid32={}", ret, self, sid32);
            return ret;
        }

        static bool JustPressed(int vk)
        {
            static SHORT prev[256] = {};
            SHORT s = GetAsyncKeyState(vk);
            bool now = (s & 0x8000) != 0;
            bool was = (prev[vk] & 0x8000) != 0;
            prev[vk] = s;
            return now && !was;
        }

        // Phase tick: hotkeys
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);

            // F7: Injection
            if (JustPressed(VK_F7))
            {
                // NOOP
            }

            // View Tree Print
            if (JustPressed(VK_F8))
            {
                DumpWindowAndLayoutTree();    
            }
            
            if (JustPressed(VK_F9))
            {
                spdlog::info("[HK] F8 -> unified view tree (Windows / Layouts / Models / Nodes)");
                DumpUnifiedViewTree();
            }
        }

        void __fastcall UpdateWindowManagerGraphsHook(fox::ui::WindowManager* self, uint32_t groupId)
        {
            UpdateWindowManagerGraphs(self, groupId);
        }

        // -----------------------------------------------------------------------------
        // Install
        // -----------------------------------------------------------------------------

        void CreateHooks()
        {
            spdlog::set_level(spdlog::level::info);

            CREATE_HOOK(SetTextForModelNodeText)
            CREATE_HOOK(SetTextForModelNodeTextInternal)
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
            CREATE_HOOK(WindowCtor)
            CREATE_HOOK(WindowDtor)
            CREATE_HOOK(ProcessWindow)
            CREATE_HOOK(FindChildWindow)
            CREATE_HOOK(FindUiWindow)
            CREATE_HOOK(UpdateWindowLayouts)

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
            CREATE_HOOK(SetModelNodeTextFontSize)
            CREATE_HOOK(SetUixModelNodeTextFontSize)
            CREATE_HOOK(SetModelNodeTextFontSpace)
            CREATE_HOOK(SetModelNodeTextColorRGB)
            CREATE_HOOK(GetModelNodeWorldVisibility)
            CREATE_HOOK(SetModelNodeTextDisplayAreaWidthOffset)
            CREATE_HOOK(ResetModelNodeTextFontSize)
            CREATE_HOOK(ResetModelNodeTextFontSpace)

            CREATE_HOOK(BuildTextAreaPack)
            CREATE_HOOK(ApplyTextAndMeasure)
            CREATE_HOOK(RunAnalysis)

            CREATE_HOOK(WindowCreate)
            // CREATE_HOOK(GetLayoutComponent)
            CREATE_HOOK(GetManagerText)

            CREATE_HOOK(RegisterUiGraphNodeCtor)
            CREATE_HOOK(GraphNodeFactory)
            CREATE_HOOK(GetStringId)

            CREATE_HOOK(CallHudMessage)
            CREATE_HOOK(CallHudMessageWithNumber)
            CREATE_HOOK(CallHudMessageWithReceiver)
            CREATE_HOOK(HudCommonCallHudMessage)
            CREATE_HOOK(InitializeHudUigDatas)

            CREATE_HOOK(AnnounceLogView)
            CREATE_HOOK(SetLayoutActive)
            CREATE_HOOK(SetUiModelNodeTranslate)

            CREATE_HOOK(UpdateWindowManagerGraphs)
            CREATE_HOOK(NewUiLayoutSharedPtr)
            CREATE_HOOK(NewUiModelSharedPtr)
            CREATE_HOOK(UiModelNodeCtor)
            CREATE_HOOK(LayoutCtor)
            CREATE_HOOK(ModelCtor)
            CREATE_HOOK(LayoutDtor)
            CREATE_HOOK(ModelDtor)
            CREATE_HOOK(ModelNodeDtor)
            CREATE_HOOK(LayoutGetLayout)
            CREATE_HOOK(GetWindowInterfaceLayout)

            CREATE_HOOK(SetupModel)
            CREATE_HOOK(ReadUiModelFile)
            CREATE_HOOK(ReadUiModelNode)
            
            CREATE_HOOK(GetWindowName)
            CREATE_HOOK(CreateChildWindows)

            //-------------------ENABLE-------------------------

            ENABLEHOOK(SetTextForModelNodeText)
            ENABLEHOOK(SetTextForModelNodeTextInternal)
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
            ENABLEHOOK(WindowCtor)
            ENABLEHOOK(WindowDtor)
            ENABLEHOOK(ProcessWindow)
            ENABLEHOOK(FindChildWindow)
            ENABLEHOOK(FindUiWindow)
            ENABLEHOOK(UpdateWindowLayouts)

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
            ENABLEHOOK(SetModelNodeTextFontSize)
            ENABLEHOOK(SetUixModelNodeTextFontSize)
            ENABLEHOOK(SetModelNodeTextFontSpace)
            ENABLEHOOK(SetModelNodeTextColorRGB)
            ENABLEHOOK(GetModelNodeWorldVisibility)
            ENABLEHOOK(SetModelNodeTextDisplayAreaWidthOffset)
            ENABLEHOOK(ResetModelNodeTextFontSize)
            ENABLEHOOK(ResetModelNodeTextFontSpace)

            ENABLEHOOK(BuildTextAreaPack)
            ENABLEHOOK(ApplyTextAndMeasure)
            ENABLEHOOK(RunAnalysis)

            ENABLEHOOK(WindowCreate)
            // ENABLEHOOK(GetLayoutComponent)
            ENABLEHOOK(GetManagerText)

            ENABLEHOOK(RegisterUiGraphNodeCtor)
            ENABLEHOOK(GraphNodeFactory)
            ENABLEHOOK(GetStringId)

            ENABLEHOOK(CallHudMessage)
            ENABLEHOOK(CallHudMessageWithNumber)
            ENABLEHOOK(CallHudMessageWithReceiver)
            ENABLEHOOK(HudCommonCallHudMessage)
            ENABLEHOOK(InitializeHudUigDatas)

            ENABLEHOOK(AnnounceLogView)
            ENABLEHOOK(SetLayoutActive)
            ENABLEHOOK(SetUiModelNodeTranslate)

            ENABLEHOOK(UpdateWindowManagerGraphs)
            ENABLEHOOK(NewUiLayoutSharedPtr)
            ENABLEHOOK(NewUiModelSharedPtr)
            ENABLEHOOK(UiModelNodeCtor)
            ENABLEHOOK(LayoutCtor)
            ENABLEHOOK(ModelCtor)
            ENABLEHOOK(LayoutDtor)
            ENABLEHOOK(ModelDtor)
            ENABLEHOOK(ModelNodeDtor)
            ENABLEHOOK(LayoutGetLayout)
            ENABLEHOOK(GetWindowInterfaceLayout)

            ENABLEHOOK(SetupModel)
            ENABLEHOOK(ReadUiModelFile)
            ENABLEHOOK(ReadUiModelNode)

            ENABLEHOOK(GetWindowName)
            ENABLEHOOK(CreateChildWindows)
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
