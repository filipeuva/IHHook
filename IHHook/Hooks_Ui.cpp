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
        // ---------- Engine opaque types ----------
        using UiLayout = void; // fox::ui::Layout
        using UiModel = void; // fox::ui::Model
        using UiModelNode = void; // fox::ui::ModelNode
        using UiModelText = void; // fox::ui::ModelNodeText
        using UiWindow = void; // fox::ui::Window
        using WindowFuncIF = void; // some WindowFunction* / factory iface

        // ---------------------------------------------------------------------
        // TARGETS / STATE
        // ---------------------------------------------------------------------
        static std::unordered_set<uint64_t> g_targetSig64s = {
            0x6E6A53858C7D348A, // Main Menu
        };

        static constexpr size_t kMaxAnnAnchors = 4;

        struct AnnAnchorSlot
        {
            void*    nodeText{};     // UiModelText*
            void*    textUnit{};     // TextUnit*
            void*    uix{};          // UixUtility*

            uint32_t sceneStr{};     // from NewUiModelText
            void*    creationCtx{};  // from NewUiModelText
        };

        static AnnAnchorSlot g_annSlots[kMaxAnnAnchors];
        static size_t        g_annSlotCount = 0;

        // optional: a simple toggle so you can turn driving on/off
        static std::atomic<bool> g_annDriveEnabled{true};

        // Map every ModelNodeText we see to its creation context.
        // This is deterministic: key = exact node pointer returned by NewUiModelText.
        static std::unordered_map<void*, std::pair<uint32_t, void*>> g_textCtxByNode;

        // Announce sentinel; you will push this once via AnnounceLogView from Lua/C++
        static constexpr const char* kAnnSentinel = "IH_ANN_SENTINEL";

        // ---------------------------------------------------------------------
        // State
        // ---------------------------------------------------------------------

        static void RegisterAnnSlot(void* nodeText, void* textUnit, void* uix,
                            uint32_t sceneStr, void* creationCtx)
        {
            if (!nodeText || !textUnit || !uix)
                return;

            // de-dupe on nodeText
            for (size_t i = 0; i < g_annSlotCount; ++i)
            {
                if (g_annSlots[i].nodeText == nodeText)
                    return;
            }

            if (g_annSlotCount >= kMaxAnnAnchors)
                return;

            AnnAnchorSlot& s = g_annSlots[g_annSlotCount++];
            s.nodeText   = nodeText;
            s.textUnit   = textUnit;
            s.uix        = uix;
            s.sceneStr   = sceneStr;
            s.creationCtx = creationCtx;

            spdlog::info("[ANN SLOT] idx={} nodeText={} textUnit={} uix={} sceneStr=#{:08X} ctx={}",
                         g_annSlotCount - 1,
                         s.nodeText, s.textUnit, s.uix, s.sceneStr, s.creationCtx);
        }
        
        static char g_annTextBuf[64];  // persistent storage for HUD string

        static void DriveAnnounceSlots()
        {
            if (g_annSlotCount == 0)
                return;

            float camo = Hooks_Camo::gCamoScore.load();
            float display = std::ceil(camo / 30);     // same math you had

            // build stable string in global buffer
            int n = std::snprintf(g_annTextBuf, sizeof(g_annTextBuf), "C:%.0f%%", camo);
            if (n < 0)
                g_annTextBuf[0] = '\0';

            for (size_t i = 0; i < g_annSlotCount; ++i)
            {
                AnnAnchorSlot& s = g_annSlots[i];
                if (!s.nodeText || !s.textUnit)
                    continue;

                // this is the path you've proven actually wins on tick
                

                spdlog::debug("[ANN JACK] Will set style");
                SetTextForModelNodeTextInternal(s.nodeText, s.textUnit, g_annTextBuf, true);

                // SetModelNodeTextFontSize(s.uix, s.nodeText, 48.f, 0.f);
                // SetModelNodeTextDisplayWidth(s.nodeText, 0.f);
                // SetModelNodeTextDisplayHeight(s.nodeText, 0.f);
                SetModelNodeTextFontSize(s.nodeText, 48.f, 0.f);
                SetModelNodeTextFontSpace(s.nodeText, 6.f, 0.f);
                // ResetModelNodeTextFontSize(s.nodeText);
                // ResetModelNodeTextFontSpace(s.nodeText);
                float v[4] = {0.f, 0.f, 0.f, 0.f};
                SetUiModelNodeTranslate(s.nodeText,v);

                if (i == 0)
                {
                    if (camo > 0.f)
                    {
                        SetModelNodeTextColorRGB(s.uix, s.nodeText, 1.f, 1.f, 1.f);
                    }  else
                    {
                        SetModelNodeTextColorRGB(s.uix, s.nodeText, 1.f, 0.3f, 0.2f); // RED ! r=1.0 g=0.3 b=0.2
                    }
                }

                // SetTextUnit(s.textUnit,g_annTextBuf, 16391, 6, 0, 48.f, 0.f, 0, 0);
                
            }
        }
    
        // ---------------------------------------------------------------------
        // Hooks
        // ---------------------------------------------------------------------

        // text hooks
        void __fastcall SetTextForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, const char* rawText,
                                                    bool isLocalized)
        {
            spdlog::debug("[STFMNT] uix={} nodeText={} textUnit={} rawText={} isLocalized={}",
                          uix, nodeText, textUnit, rawText ? rawText : "", isLocalized);

            if (rawText && std::strcmp(rawText, kAnnSentinel) == 0)
            {
                uint32_t sceneStr   = 0;
                void*    creationCtx = nullptr;

                if (auto it = g_textCtxByNode.find(nodeText); it != g_textCtxByNode.end())
                {
                    sceneStr    = it->second.first;
                    creationCtx = it->second.second;
                }

                RegisterAnnSlot(nodeText, textUnit, uix, sceneStr, creationCtx);
            }

            SetTextForModelNodeText(uix, nodeText, textUnit, rawText, isLocalized);
        }

        void __fastcall SetTextForModelNodeTextInternalHook(void* nodeText, void* textUnit, const char* rawText,
                                                            bool isLocalized)
        {
            spdlog::debug("[STFMNTI] nodeText={} textUnit={} rawText={} isLocalized={}", nodeText, textUnit,
                          rawText, isLocalized);
            SetTextForModelNodeTextInternal(nodeText, textUnit, rawText, isLocalized); // original
        }

        void __fastcall SetTextUnitsForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, uint64_t stringId)
        {
            spdlog::debug("[STUFMNT] uix={} nodeText={} textUnit={} stringId={}", uix, nodeText, textUnit, stringId);
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

        bool __fastcall IsHaveModelNodeCommonHook(void* selfUixUtility, const void* model, StrCode stringId)
        {
                spdlog::debug("[IsHaveModelNodeCommonHook] IsHaveModelNodeCommon model={} sid32=#{:08X}",
                              model, stringId);
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
            auto ret = NewUiModelText(sceneStr, creationCtx, a2, a3);
            spdlog::debug("[NewUiModelText] node={} sceneStr=#{:08X} ctx={}", ret, sceneStr, creationCtx);
            
            return ret;
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
            auto h = GetWindowHandle(mgr, windowFunction);
            return h;
        }

        void __fastcall SetLayoutInfoHook(void* windowHandle, const void* layoutInfo)
        {
            SetLayoutInfo(windowHandle, layoutInfo);
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

        static bool IsAnnTextUnit(void* tu)
        {
            for (size_t i = 0; i < g_annSlotCount; ++i)
            {
                if (g_annSlots[i].textUnit == tu)
                    return true;
            }
            return false;
        }

        void __fastcall SetTextUnitHook(void* selfTextUnit, char* text, uint32_t flags, uint16_t p3, uint16_t p4,
                                        float size, float tracking, uint32_t p7, uint32_t p8)
        {
            // clamp style for our hijacked announce slots
            if (IsAnnTextUnit(selfTextUnit))
            {
                spdlog::info("[ANN JACK] Setting styles");
                // example: smaller, tighter HUD text
                size     = 48.0f;
                tracking = 24.0f;
            }

            SetTextUnit(selfTextUnit, text, flags, p3, p4, size, tracking, p7, p8);
            spdlog::info("[SET TU] selfTextUnit={} text={} flags={} p3={} p4={} size={} tracking={} p7={} p8={}",
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
            spdlog::debug("[CLC] childComp={} parentComp={} portPtr={}", childComp, parentComp, portPtr);
            ConnectLayoutComponent(childComp, parentComp, portPtr);
        }

        void __fastcall ConnectLayoutUtilityComponentHook(void* childComp, void* parentComp, StrCode portSid)
        {
            spdlog::debug(
                "[CLU] childComp={} parentComp={} portSid=#{:08X}",
                childComp, parentComp, portSid);

            ConnectLayoutUtilityComponent(childComp, parentComp, portSid);
        }

        void __fastcall ConnectChildWindowToNodeHook(void* window, void* windowHandle, void* parentComp, void* portPtr)
        {
            spdlog::debug("[ANCHOR] window={} handle={} parentComp={} portPtr={}",
                          window, windowHandle, parentComp, portPtr);
            
            ConnectChildWindowToNode(window, windowHandle, parentComp, portPtr);
        }

        void __fastcall ConnectChildWindowToRootHook(void* window, void* windowHandle)
        {
            ConnectChildWindowToRoot(window, windowHandle);
        }

        void* __fastcall GetConnectModelHook(void* self /*ModelNodeConnection**/, void* outTransform /*=nullptr*/)
        {
            auto ret = GetConnectModel(self, outTransform);
            spdlog::debug("[GetConnectModel] model={} self={} outTransform={}", ret, self, outTransform);
            return ret;
        }

        void __fastcall ConnectWindowToParentHook(void* windowFunction, void* parentComp, void* portPtr)
        {
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
            spdlog::debug("[SetUixModelNodeTextFontSize] uix={} modelNodeText={} px={} secondary={}", uix, nodeText, px, secondary);
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

        void __fastcall RegisterUiGraphNodeCtorHook(uint32_t sig32, void* ctorThunk)
        {
            RegisterUiGraphNodeCtor(sig32, ctorThunk);
            spdlog::debug("[REG UI GRAPH NODE] sig32={} ctorThunk={}", sig32, ctorThunk);
        }

        StrCode32* __fastcall GetStringIdHook(StrCode* out, const char* string)
        {
            StrCode32* sid = GetStringId(out, string);

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
            // spdlog::debug("[LAYOUTCOMPONENT] retComponent={} self={}", retComponent, self);
            return retComponent;
        }

        const char* __fastcall GetManagerTextHook(void* self, uint32_t sid32)
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

        // static void InjectAnnSibling(const char* text)
        // {
        //     if (!g_annAnchor.ready || !g_annAnchor.attached)
        //     {
        //         spdlog::debug("[ANN INJECT] anchor not ready/attached");
        //         return;
        //     }
        //
        //     const char* useText = text ? text : "IH_ANN_INJECT";
        //
        //     // Create a new ModelNodeText using the same sceneStr/creationCtx as the sentinel node.
        //     void* nodeText = NewUiModelText(g_annAnchor.sceneStr, g_annAnchor.creationCtx, nullptr, nullptr);
        //     if (!nodeText)
        //     {
        //         spdlog::debug("[ANN INJECT] NewUiModelText failed");
        //         return;
        //     }
        //
        //     // Minimal layout; tune as needed.
        //     SetModelNodeTextDisplayWidth(nodeText, 256.0f);
        //     SetModelNodeTextDisplayHeight(nodeText, 48.0f);
        //     SetModelNodeTextDisplayAreaWidthOffset(nodeText, 0.0f, 0.0f);
        //
        //     // Use the same UIX path as the factory does; let it allocate its own TextUnit.
        //     SetTextForModelNodeText(g_annAnchor.uix, nodeText, nullptr, useText, false);
        //
        //     // Attach as sibling in the same port as the sentinel node.
        //     NodeConnectShim(g_annAnchor.owner, g_annAnchor.parentComp, g_annAnchor.portPtr, nodeText);
        //
        //     spdlog::info("[ANN INJECT] nodeText={} owner={} parentComp={} portPtr={}",
        //                  nodeText, g_annAnchor.owner, g_annAnchor.parentComp, g_annAnchor.portPtr);
        // }
        
        // Phase tick: hotkeys
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);

            // F7: toggle on/off driving of ANN anchors
            if (JustPressed(VK_F7))
            {
                bool enabled = !g_annDriveEnabled.load();
                g_annDriveEnabled.store(enabled);
                spdlog::info("[ANN DRIVE] toggled {}", enabled ? "ON" : "OFF");
            }
            
            if (g_annDriveEnabled.load())
            {
                DriveAnnounceSlots();
            }
        }

        // -----------------------------------------------------------------------------
        // Install
        // -----------------------------------------------------------------------------

        void CreateHooks()
        {
            spdlog::set_level(spdlog::level::debug);

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
            CREATE_HOOK(GetLayoutComponent)
            CREATE_HOOK(GetManagerText)

            CREATE_HOOK(RegisterUiGraphNodeCtor)
            CREATE_HOOK(GetStringId)

            CREATE_HOOK(CallHudMessage)
            CREATE_HOOK(CallHudMessageWithNumber)
            CREATE_HOOK(CallHudMessageWithReceiver)
            CREATE_HOOK(HudCommonCallHudMessage)
            CREATE_HOOK(InitializeHudUigDatas)

            CREATE_HOOK(AnnounceLogView)
            CREATE_HOOK(SetLayoutActive)
            CREATE_HOOK(SetUiModelNodeTranslate)

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
            ENABLEHOOK(GetLayoutComponent)
            ENABLEHOOK(GetManagerText)

            ENABLEHOOK(RegisterUiGraphNodeCtor)
            ENABLEHOOK(GetStringId)

            ENABLEHOOK(CallHudMessage)
            ENABLEHOOK(CallHudMessageWithNumber)
            ENABLEHOOK(CallHudMessageWithReceiver)
            ENABLEHOOK(HudCommonCallHudMessage)
            ENABLEHOOK(InitializeHudUigDatas)

            ENABLEHOOK(AnnounceLogView)
            ENABLEHOOK(SetLayoutActive)
            ENABLEHOOK(SetUiModelNodeTranslate)
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
