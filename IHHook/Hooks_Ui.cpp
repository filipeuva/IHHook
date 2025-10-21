#include "Hooks_Ui.h"
#include <filesystem>//exename

#include "spdlog/spdlog.h"
#include "MinHook.h"
#include "HookMacros.h"

#include "IHHook.h"//DEBUGNOW
#include "hooks/mgsvtpp_func_typedefs.h"

namespace IHHook
{
    namespace Hooks_Ui
    {
        // ================== env capture ==================
        struct TextEnv
        {
            void* modelFile; // from CreateInfo
            void* fileHeader; // from Read/CreateInfo
            void* nodeHeader; // from Read/CreateInfo
            uint32_t* strCodes; // from Read
            void* creationCtx; // from UiModelText::new
            uint32_t sceneStr; // from UiModelText::new
        };

        static std::atomic<TextEnv*> gLastEnv{nullptr};

        // thread-local handoff to correlate new() → Read() → CreateInfo()
        thread_local void* tlsPendingNewText = nullptr;
        thread_local TextEnv tlsEnv{};

        // ================== synth creation ==================
        static void* CreateAndAttachTextNode(const char* text)
        {
            auto* snap = gLastEnv.load(std::memory_order_acquire);
            if (!snap)
            {
                spdlog::warn("[UiTextAttach] no env captured yet; skip");
                return nullptr;
            }

            // 1) construct with same scene/creation family
            void* node = NewUiModelText(snap->sceneStr, snap->creationCtx, nullptr, nullptr);
            if (!node)
            {
                spdlog::warn("[UiTextAttach] new failed");
                return nullptr;
            }

            // 2) mirror engine order: Read -> CreateInfo
            uint32_t outName = 0;
            __try
            {
                ReadNode(node, snap->fileHeader, snap->nodeHeader, snap->strCodes, &outName);
                InitModelNodeText(node, snap->modelFile, snap->fileHeader, snap->nodeHeader);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                spdlog::error("[UiTextAttach] exception during Read/CreateInfo for node {}", fmt::ptr(node));
                return nullptr;
            }

            // 3) visible + optional text
            SetNodeVisibility(node, true);
            if (text && *text)
            {
                // uixUtilityImpl / textUnit are optional for simple textbox updates
                SetTextForModelNodeText(nullptr, node, nullptr, text, false);
            }

            spdlog::info("[UiTextAttach] attached UiModelText {}", fmt::ptr(node));
            return node;
        }

        // ================== sample trigger ==================
        // call once from your existing UpdatePhaseUiHook after UpdatePhaseUi()
        static void UiText_Tick()
        {
            // press F7 to spawn a test box once you’ve seen at least one legit UiModelText
            static bool armed = true;
            if (armed && (GetAsyncKeyState(VK_F8) & 1))
            {
                spdlog::info("[UiTextAttach] Bombs away !!!");
                armed = false;
                CreateAndAttachTextNode("Hello World");
            }
        }


        // --------------------------------------------------------------------------------------------------------------Hooks 
        void __fastcall ScopeZoomUiUpdateHook(void* self)
        {
            // spdlog::debug(__func__);

            ScopeZoomUiUpdate(self);
        } //ScopeZoomUiUpdateHook

        void __fastcall ScopeZoomUiUpdateSightHook(void* self)
        {
            spdlog::debug(__func__);

            // call game code
            ScopeZoomUiUpdateSight(self);
        } //ScopeZoomUiUpdateSightHook


        void __fastcall ScopeZoomUiUpdateScopeLengthHook(void* self)
        {
            spdlog::debug(__func__);

            ScopeZoomUiUpdateScopeLength(self);
        } //ScopeZoomUiUpdateScopeLength

        void __fastcall ScopeZoomUiSetHelpAssetHook(void* self, void* layoutA, void* layoutB)
        {
            spdlog::debug(__func__);

            ScopeZoomUiSetHelpAsset(self, layoutA, layoutB);
        } //ScopeZoomUiSetHelpAssetHook

        void __fastcall SetTextForModelNodeTextHook(void* uixUtilityImpl, void* modelNodeText, void* textUnit,
                                                    const char* rawText, bool isLocalized)
        {
            // spdlog::debug(
            //     "SetTextForModelNodeTextHook uixUtilityImpl={} modelNodeText={} textUnit={} rawText={} isLocalized={}",
            //     uixUtilityImpl, modelNodeText, textUnit, (rawText ? rawText : "(null)"), isLocalized);

            SetTextForModelNodeText(uixUtilityImpl, modelNodeText, textUnit, rawText, isLocalized);
        } //SetTextForModelNodeTextHook

        void __fastcall InitMbStageSpotHook(void* self)
        {
            spdlog::debug(__func__);

            InitMbStageSpot(self);
        } //InitMbStageSpotHook

        void __fastcall InitPhaseUiHook(void* phase) // STALLS
        {
            spdlog::debug(__func__);

            InitPhaseUi(phase);
        } //InitPhaseUiHook

        void __fastcall UpdatePhaseUiHook(void* phase)
        // This is a Tick function, probably propagated from a global Game::Update
        {
            // spdlog::debug(__func__);

            UpdatePhaseUi(phase);

            UiText_Tick();

            // if (GetAsyncKeyState(VK_F8) & 1)
            // {
            // }
        } //UpdatePhaseUiHook

        void __fastcall SetNodeVisibilityWrapperHook(void* anyMgr, void* thisNode, bool visible)
        {
            // spdlog::debug(__func__);

            SetNodeVisibilityWrapper(anyMgr, thisNode, visible);
        } //SetNodeVisibilityWrapperHook

        void __fastcall SetNodeVisibilityHook(void* thisNode, bool visible)
        {
            // spdlog::debug(__func__);

            SetNodeVisibility(thisNode, visible);
        } //SetNodeVisibilityHook

        bool __fastcall IsNodeVisibleHook(void* anyMgr, void* node)
        {
            // spdlog::debug(__func__);

            return IsNodeVisible(anyMgr, node);
        } //IsNodeVisibleHook

        void* __fastcall GetUixLayoutHook(void* uix, const void* windowIface, uint64_t stringId)
        {
            spdlog::debug("GetUixLayoutHook(uix = {}, windowIface = {}, stringId = {})", uix, windowIface, stringId);

            void* layout = GetUixLayout(uix, windowIface, stringId);

            return layout;
        } //GetUixLayoutHook

        void* /*UixLayout**/ __fastcall GetModelWrapperHook(void* thisLayout, void* outModel /*UixLayout**/,
                                                            uint32_t stringId /*StrCode32*/)
        {
            spdlog::debug(__func__);

            return GetModelWrapper(thisLayout, outModel, stringId);
        } //GetModelWrapperHook

        void* /*ModelNode*/ __fastcall CreateModelNodeHook(void* thisModel, void* modelFile, void* fileHeader,
                                                           void* nodeHeader,
                                                           uint32_t* strCode32s, uint64_t* param_5, uint32_t* param_6)
        {
            spdlog::debug(__func__);

            auto modelNode = CreateModelNode(thisModel, modelFile, fileHeader, nodeHeader, strCode32s, param_5,
                                             param_6);
            return modelNode;
        } //CreateModelNodeHook

        void* /*ModelNode*/ __fastcall NewUiModelTextHook(uint32_t sceneStr, void* creationCtx, void* opt0,
                                                          void* opt1)
        {
            spdlog::debug(__func__);

            // return NewUiModelText(sceneStr, creationCtx, opt0, opt1);
            void* node = NewUiModelText(sceneStr, creationCtx, opt0, opt1);
            tlsPendingNewText = node;
            tlsEnv.sceneStr = sceneStr;
            tlsEnv.creationCtx = creationCtx;
            spdlog::debug("[UiTextAttach] new UiModelText node={}", fmt::ptr(node));
            return node;
        } //NewUiModelTextHook

        void* __fastcall GetModelNodeCommonHook(const void* model, uint64_t stringId)
        {
            spdlog::debug(__func__);

            return GetModelNodeCommon(model, stringId);
        } //GetModelNodeCommonHook

        void* __fastcall GetModelNodeFromIndexHook(const void* thisModel, int index)
        {
            // spdlog::debug(__func__);

            return GetModelNodeFromIndex(thisModel, index);
        } //GetModelNodeFromIndexHook

        const void* __fastcall LoadCreationContextHook(const void* serializedBlob, void* outCtx)
        {
            spdlog::debug(__func__);

            return LoadCreationContext(serializedBlob, outCtx);
        } //LoadCreationContextHook

        void __fastcall ReadNodeHook(void* node, void* fileHeader /*UiModelFileHeader**/,
                                     void* nodeHeader /*UiModelNodeHeader**/, uint32_t* strCode32s, uint32_t* outName)
        {
            spdlog::debug(__func__);

            // ReadNode(thisPtr, file, nodeHeader, strCode32s, outName);
            ReadNode(node, fileHeader, nodeHeader, strCode32s, outName);

            if (node == tlsPendingNewText)
            {
                tlsEnv.fileHeader = fileHeader;
                tlsEnv.nodeHeader = nodeHeader;
                tlsEnv.strCodes = strCode32s;
                spdlog::debug("[UiTextAttach] capture Read env node={} fileHeader={} nodeHeader={} strTbl={}",
                              fmt::ptr(node), fmt::ptr(fileHeader), fmt::ptr(nodeHeader), fmt::ptr(strCode32s));
            }
        } //LoadCreationContextHook

        void __fastcall InitModelNodeTextHook(void* node, void* modelFile, void* fileHeader, void* nodeHeader)
        {
            spdlog::debug(__func__);

            InitModelNodeText(node, modelFile, fileHeader, nodeHeader);

            if (node == tlsPendingNewText)
            {
                tlsEnv.modelFile = modelFile;

                // publish coherent snapshot
                auto* prev = gLastEnv.load(std::memory_order_acquire);
                auto* snap = new TextEnv(tlsEnv);
                gLastEnv.store(snap, std::memory_order_release);
                if (prev) delete prev;

                spdlog::info("[UiTextAttach] env ready node={} modelFile={} fileHeader={} nodeHeader={}",
                             fmt::ptr(node), fmt::ptr(modelFile), fmt::ptr(fileHeader), fmt::ptr(nodeHeader));

                tlsPendingNewText = nullptr;
                tlsEnv = {};
            }
        } //LoadCreationContextHook

        void CreateHooks()
        {
            CREATE_HOOK(SetTextForModelNodeText)
            CREATE_HOOK(IsNodeVisible)
            CREATE_HOOK(UpdatePhaseUi)
            CREATE_HOOK(SetNodeVisibilityWrapper)
            CREATE_HOOK(SetNodeVisibility)
            CREATE_HOOK(GetUixLayout)
            CREATE_HOOK(GetModelWrapper)
            CREATE_HOOK(CreateModelNode)
            CREATE_HOOK(NewUiModelText)
            CREATE_HOOK(GetModelNodeCommon)
            CREATE_HOOK(GetModelNodeFromIndex)
            CREATE_HOOK(LoadCreationContext)
            CREATE_HOOK(ReadNode)
            CREATE_HOOK(InitModelNodeText)
            // CREATE_HOOK(ScopeZoomUiUpdate)
            // CREATE_HOOK(ScopeZoomUiUpdateSight)
            // CREATE_HOOK(ScopeZoomUiUpdateScopeLength)
            // CREATE_HOOK(ScopeZoomUiSetHelpAsset)
            // CREATE_HOOK(InitPhaseUi)
            // CREATE_HOOK(InitMbStageSpot)

            ENABLEHOOK(SetTextForModelNodeText)
            ENABLEHOOK(IsNodeVisible)
            ENABLEHOOK(UpdatePhaseUi)
            ENABLEHOOK(SetNodeVisibilityWrapper)
            ENABLEHOOK(SetNodeVisibility)
            ENABLEHOOK(GetUixLayout)
            ENABLEHOOK(GetModelWrapper)
            ENABLEHOOK(CreateModelNode)
            ENABLEHOOK(NewUiModelText)
            ENABLEHOOK(GetModelNodeCommon)
            ENABLEHOOK(GetModelNodeFromIndex)
            ENABLEHOOK(LoadCreationContext)
            ENABLEHOOK(ReadNode)
            ENABLEHOOK(InitModelNodeText)
            // ENABLEHOOK(ScopeZoomUiUpdate)
            // ENABLEHOOK(ScopeZoomUiUpdateSight)
            // ENABLEHOOK(ScopeZoomUiUpdateScopeLength)
            // ENABLEHOOK(ScopeZoomUiSetHelpAsset)
            // ENABLEHOOK(InitPhaseUi)
            // ENABLEHOOK(InitMbStageSpot)
        } //CreateHooks


        int CreateLibs(lua_State* L)
        {
            spdlog::debug(__func__);

            luaL_Reg libFuncs[] = {

                {NULL, NULL} //GOTCHA: crashes without
            };
            luaI_openlib(L, "IhkUi", libFuncs, 0);
            return 1;
        } //CreateLibs
    } //namespace Hooks_FOV
} //namespace IHHook
