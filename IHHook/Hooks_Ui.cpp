#include "Hooks_Ui.h"
#include <filesystem>//exename

#include "spdlog/spdlog.h"
#include "MinHook.h"
#include "HookMacros.h"

#include "IHHook.h"//DEBUGNOW
#include "hooks/mgsvtpp_func_typedefs.h"

#include <windows.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <deque>

#include "spdlog/fmt/fmt.h"

namespace IHHook
{
    namespace Hooks_Ui
    {
        // =====================================================
        //                 SAFE MEMORY PROBES
        // =====================================================
        static inline bool IsReadable(const void* p, size_t len)
        {
            if (!p) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT) return false;
            if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;

            const DWORD kReadMask =
                PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

            const auto base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const auto end = base + mbi.RegionSize;
            const auto start = reinterpret_cast<uintptr_t>(p);
            const auto finish = start + len;
            if (finish < start) return false; // overflow
            if (finish > end) return false; // crosses region
            return (mbi.Protect & kReadMask) != 0;
        }

        template <class T>
        static inline bool SafeRead(const void* p, T& out)
        {
            if (!IsReadable(p, sizeof(T))) return false;
            out = *reinterpret_cast<const T*>(p);
            return true;
        }

        template <class T>
        static inline bool SafeReadPtr(const void* p, T*& out)
        {
            void* tmp = nullptr;
            if (!SafeRead(p, tmp)) return false;
            out = reinterpret_cast<T*>(tmp);
            return true;
        }

        static inline bool SafeNodeVisible(void* node)
        {
            if (!node) return false;
            uint16_t flags{};
            if (!SafeRead(reinterpret_cast<uint8_t*>(node) + 0x70, flags)) return false;
            return (flags & 0x1) != 0;
        }

        // =====================================================
        //                    CAPTURE STATE
        // =====================================================
        struct TextSeen
        {
            void* node{};
            std::string raw;
            uint64_t t{};
        };

        static std::deque<TextSeen> g_recent;
        static constexpr size_t kRecentMax = 128;

        static std::unordered_map<void*, uint32_t> g_nodeName; // node* -> StrCode32 name (from ReadNode)
        static std::unordered_map<void*, std::string> g_nodeText;
        // node* -> last raw text (from SetTextForModelNodeText)
        static std::unordered_map<void*, void*> g_nodeUix; // node* -> last uix that wrote to it

        static std::vector<void*> g_models; // known models (we dedupe append)
        static thread_local void* tls_lastUix = nullptr; // transient, set by GetUixLayoutHook

        // simple knobs for the demo replace
        static std::string gFindPattern = "SLEEP GRENADE"; // change at runtime if you want
        static std::string gReplaceText = "HELLO WORLD";

        // =====================================================
        //                    DUMP HELPERS
        // =====================================================
        static void DumpModel(void* model)
        {
            if (!model) return;

            uint32_t count{};
            void** nodes{};
            void* root{};

            if (!SafeRead(reinterpret_cast<uint8_t*>(model) + 0x90, count)) return;
            if (!SafeReadPtr(reinterpret_cast<uint8_t*>(model) + 0x98, nodes)) return;
            SafeReadPtr(reinterpret_cast<uint8_t*>(model) + 0x80, root);

            const bool mvis = root ? SafeNodeVisible(root) : false;
            spdlog::info("  Model={} nodes={} root={} vis={}",
                         fmt::ptr(model), count, fmt::ptr(root), mvis);

            if (!nodes || !count) return;
            if (!IsReadable(nodes, size_t(count) * sizeof(void*))) return;

            auto inModel = [&](void* p)-> bool
            {
                if (!p) return false;
                for (uint32_t i = 0; i < count; ++i) if (nodes[i] == p) return true;
                return false;
            };

            // best-effort parent discovery (we don't know the exact offset; probe a few common ones)
            auto findParent = [&](void* n)-> void* {
                static const size_t kProbe[] = {
                    0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x68, 0x70, 0x78, 0x88, 0x90
                };
                for (size_t off : kProbe)
                {
                    void* cand{};
                    if (SafeReadPtr(reinterpret_cast<uint8_t*>(n) + off, cand) && inModel(cand)) return cand;
                }
                return nullptr;
            };

            std::unordered_map<void*, std::vector<void*>> children;
            children.reserve(count + 1);
            for (uint32_t i = 0; i < count; ++i)
            {
                void* n = nodes[i];
                children[findParent(n)].push_back(n);
            }

            auto printNode = [&](int indent, void* n)
            {
                const bool vis = SafeNodeVisible(n);
                uint32_t name{};
                if (auto it = g_nodeName.find(n); it != g_nodeName.end()) name = it->second;

                auto it2 = g_nodeText.find(n);
                if (it2 != g_nodeText.end() && !it2->second.empty())
                {
                    spdlog::info("{:>{}}- node={} vis={} name=0x{:08X} txt='{}'",
                                 "", indent * 2, fmt::ptr(n), vis, name, it2->second);
                }
                else
                {
                    spdlog::info("{:>{}}- node={} vis={} name=0x{:08X}",
                                 "", indent * 2, fmt::ptr(n), vis, name);
                }
            };

            std::function<void(void*, int)> dfs = [&](void* n, int d)
            {
                if (!n) return;
                printNode(d, n);
                auto it = children.find(n);
                if (it != children.end()) for (void* c : it->second) dfs(c, d + 1);
            };

            if (root) dfs(root, 1);

            // orphan roots (if parent probing missed a root)
            for (uint32_t i = 0; i < count; ++i)
            {
                void* n = nodes[i];
                if (!n || n == root) continue;
                if (!children.count(findParent(n))) dfs(n, 1);
            }
        }

        static void UiDump_NoLocks()
        {
            spdlog::info("=== UI Dump: {} model(s) ===", g_models.size());
            for (void* m : g_models) DumpModel(m);
            spdlog::info("=== UI Dump end ===");
        }

        // =====================================================
        //                 TEXT REPLACE (PATTERN)
        // =====================================================
        static void UiReplaceMostRecentMatch_NoLocks()
        {
            TextSeen pick{};
            for (auto& rec : g_recent)
            {
                if (rec.node && !gFindPattern.empty() &&
                    rec.raw.find(gFindPattern) != std::string::npos)
                {
                    pick = rec;
                    break;
                }
            }
            if (!pick.node)
            {
                spdlog::warn("[UiReplace] no recent node matches '{}'", gFindPattern);
                return;
            }

            void* uix = nullptr;
            if (auto it = g_nodeUix.find(pick.node); it != g_nodeUix.end()) uix = it->second;

            spdlog::info("[UiReplace] node={} match='{}' -> '{}'", fmt::ptr(pick.node), pick.raw, gReplaceText);

            if (IsReadable(pick.node, sizeof(void*)))
            {
                SetNodeVisibility(pick.node, true); // ensure visible (no parent walk here)
            }

            if (!SetTextForModelNodeText)
            {
                spdlog::warn("[UiReplace] SetTextForModelNodeText not bound");
                return;
            }

            if (!IsReadable(pick.node, sizeof(void*)))
            {
                spdlog::warn("[UiReplace] node pointer not readable");
                return;
            }

            SetTextForModelNodeText(uix, pick.node, nullptr, gReplaceText.c_str(), /*isLocalized*/false);

            g_nodeText[pick.node] = gReplaceText;
            g_recent.push_front({pick.node, gReplaceText, GetTickCount64()});
            if (g_recent.size() > kRecentMax) g_recent.pop_back();

            spdlog::info("[UiReplace] done");
        }

        // =====================================================
        //                       HOTKEYS
        // =====================================================
        static void UiHotkeys()
        {
            if (GetAsyncKeyState(VK_F8) & 1) UiDump_NoLocks(); // dump hierarchy
            if (GetAsyncKeyState(VK_F9) & 1) UiReplaceMostRecentMatch_NoLocks(); // replace most recent match
        }

        // call this from your existing UpdatePhaseUiHook (or similar per-frame/tick site)
        void Ui_OnTick()
        {
            UiHotkeys();
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

        void __fastcall SetTextForModelNodeTextHook(void* selfUixUtilityImpl, void* node, void* textNode,
                                                    const char* rawText, bool isLocalized)
        {
            // spdlog::debug(
            //     "SetTextForModelNodeTextHook uixUtilityImpl={} modelNodeText={} textUnit={} rawText={} isLocalized={}",
            //     uixUtilityImpl, modelNodeText, textUnit, (rawText ? rawText : "(null)"), isLocalized);

            if (node)
            {
                if (selfUixUtilityImpl) g_nodeUix[node] = selfUixUtilityImpl;
                g_nodeText[node] = rawText ? rawText : "";
                g_recent.push_front({node, g_nodeText[node], GetTickCount64()});
                if (g_recent.size() > kRecentMax) g_recent.pop_back();
            }
            SetTextForModelNodeText(selfUixUtilityImpl, node, textNode, rawText, isLocalized);
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

            Ui_OnTick();

            // if (GetAsyncKeyState(VK_F8) & 1)
            // {
            // }
        } //UpdatePhaseUiHook

        void __fastcall SetNodeVisibilityWrapperHook(void* anyMgr, void* node, bool visible)
        {
            // spdlog::debug(__func__);

            SetNodeVisibilityWrapper(anyMgr, node, visible);
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

            tls_lastUix = uix;
            
            void* layout = GetUixLayout(uix, windowIface, stringId);
            return layout;
        } //GetUixLayoutHook

        void* /*UixLayout**/ __fastcall GetModelWrapperHook(void* thisLayout, void* outModel /*UixLayout**/,
                                                            uint32_t stringId /*StrCode32*/)
        {
            spdlog::debug(__func__);
            auto model = GetModelWrapper(thisLayout, outModel, stringId);


            return model;
        } //GetModelWrapperHook

        void* /*ModelNode*/ __fastcall CreateModelNodeHook(void* thisModel, void* modelFile, void* fileHeader,
                                                           void* nodeHeader,
                                                           uint32_t* strCode32s, uint64_t* param_5, uint32_t* param_6)
        {
            spdlog::debug(__func__);

            auto modelNode = CreateModelNode(thisModel, modelFile, fileHeader, nodeHeader, strCode32s, param_5,
                                             param_6);
            
            if (thisModel && std::find(g_models.begin(), g_models.end(), thisModel) == g_models.end())
                g_models.push_back(thisModel);
            
            return modelNode;
        } //CreateModelNodeHook

        void* /*ModelNode*/ __fastcall NewUiModelTextHook(uint32_t sceneStr, void* creationCtx, void* opt0,
                                                          void* opt1)
        {
            spdlog::debug(__func__);

            // return NewUiModelText(sceneStr, creationCtx, opt0, opt1);
            void* node = NewUiModelText(sceneStr, creationCtx, opt0, opt1);
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

            uint32_t name = 0;
            if (outName && IsReadable(outName, sizeof(uint32_t))) name = *outName;
            if (name) g_nodeName[node] = name;
            if (tls_lastUix) g_nodeUix[node] = tls_lastUix;
            
            ReadNode(node, fileHeader, nodeHeader, strCode32s, outName);
        } //LoadCreationContextHook

        void __fastcall InitModelNodeTextHook(void* node, void* modelFile, void* fileHeader, void* nodeHeader)
        {
            spdlog::debug(__func__);

            InitModelNodeText(node, modelFile, fileHeader, nodeHeader);
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
