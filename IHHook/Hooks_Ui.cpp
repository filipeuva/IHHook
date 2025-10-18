#include "Hooks_Ui.h"
#include <filesystem>//exename

#include "spdlog/spdlog.h"
#include "MinHook.h"
#include "HookMacros.h"

#include "IHHook.h"//DEBUGNOW
#include "hooks/mgsvtpp_func_typedefs.h"

#define VTIDX_UI_SHOW    (0x2A8/8)  // ui->Show(node, showFlag)
#define VTIDX_DRAW_SUBM  (0x708/8)  // draw->SubmitText(node, ctx, text, a5)

namespace IHHook
{
    namespace Hooks_Ui
    {
        enum OverrideMode : int { MODE_OFF = 0, MODE_ONLY_WHEN_NOT_ADS = 1, MODE_ALWAYS = 2 };

        static std::atomic<int> gMode{MODE_ONLY_WHEN_NOT_ADS};
        static std::atomic<int> gDoShow{1};
        static std::atomic<int> gEnableShadow{1};

        static char gLabel[32] = "Hello";
        static char gValue[64] = "World";

        // Cached fn ptrs (set once layout binds; never call inside SetZoomHelpAsset)
        using ShowFn = void(*)(void* ui, void* node, uint64_t show);
        using SubmitFn = void(*)(void* draw, void* node, void* ctx, const char* txt, int a5);
        static std::atomic<ShowFn> gShow{nullptr};
        static std::atomic<SubmitFn> gSubmit{nullptr};

        template <class T=void*>
        static inline T RP(void* base, size_t off) { return *(T*)((uint8_t*)base + off); }

        static inline void** VT(void* obj) { return obj ? *(void***)obj : nullptr; }

        // ---------- hooks ----------

        static void PostWriteZoom(void* self)
        {
            spdlog::debug("0");
            const int mode = gMode.load(std::memory_order_relaxed);
            if (mode == MODE_OFF) return;

            spdlog::debug("1");
            void* sightData = RP(self, 0x50);
            if (!sightData) return;
            const uint8_t flags = *(uint8_t*)((uint8_t*)sightData + 0x328);
            if (mode == MODE_ONLY_WHEN_NOT_ADS && (flags & 1)) return;

            spdlog::debug("2");
            // nodes first; prefer variant B, fallback A
            void* nLabel = RP(self, 0x198);
            void* nMain = RP(self, 0x1A0);
            void* nShadow = RP(self, 0x1A8);
            if (!nMain)
            {
                nLabel = RP(self, 0x178);
                nMain = RP(self, 0x180);
                nShadow = RP(self, 0x188);
            }
            if (!nMain) return;

            spdlog::debug("3");
            // services
            void* ui = RP(self, 0x60);
            void* mgr48 = RP(self, 0x48);
            void* draw = mgr48 ? RP<void*>(mgr48, 0x20) : nullptr;
            void* ctx = RP(self, 0x80);
            if (!ui || !draw || !ctx) return;

            spdlog::debug("4");
            // cached fn ptrs; do not touch vtables now
            SubmitFn Submit = gSubmit.load(std::memory_order_acquire);
            ShowFn Show = gShow.load(std::memory_order_acquire);
            if (!Submit) return;

            spdlog::debug("5");
            const bool useShow = gDoShow.load(std::memory_order_relaxed) != 0;
            const bool useShadow = gEnableShadow.load(std::memory_order_relaxed) != 0;

            if (useShow && Show)
            {
                if (nLabel)
                {
                    spdlog::debug("6");
                    Show(ui, nLabel, 1);
                }
                spdlog::debug("7");
                Show(ui, nMain, 1);
                if (useShadow && nShadow)
                {
                    spdlog::debug("8");
                    Show(ui, nShadow, 1);
                }
            }
            // spdlog::debug("9");
            if (nLabel) Submit(draw, nLabel, ctx, gLabel, 1);
            // spdlog::debug("10");
            // Submit(draw, nMain, ctx, gValue, 1);
            // spdlog::debug("11");
            // if (useShadow && nShadow) Submit(draw, nShadow, ctx, gValue, 1);
        }


        // Hooks 
        void __fastcall ScopeZoomUiUpdateHook(void* self)
        {
            spdlog::debug(__func__);

            ScopeZoomUiUpdate(self);

            if (RP<void*>(self,0x1A0) || RP<void*>(self,0x180))
            {
                PostWriteZoom(self);
            }
        } //ScopeZoomUiUpdateHook

        void __fastcall ScopeZoomUiSetHelpAssetHook(void* self, void* layoutA, void* layoutB)
        {
            spdlog::debug(__func__);

            ScopeZoomUiSetHelpAsset(self, layoutA, layoutB);

            void* ui = RP(self, 0x60);
            void* ctx = RP(self, 0x80);
            (void)ctx; // just to verify non-null binding
            void* mgr48 = RP(self, 0x48);
            void* draw = mgr48 ? RP<void*>(mgr48, 0x20) : nullptr;

            if (!ui || !draw) return;

            void** uvt = VT(ui);
            void** dvt = VT(draw);
            if (!uvt || !dvt) return;

            auto show = (ShowFn)uvt[VTIDX_UI_SHOW];
            auto submit = (SubmitFn)dvt[VTIDX_DRAW_SUBM];

            // publish atomically; never touched again
            gShow.store(show, std::memory_order_release);
            gSubmit.store(submit, std::memory_order_release);
        }

        void CreateHooks()
        {
            CREATE_HOOK(ScopeZoomUiUpdate)
            CREATE_HOOK(ScopeZoomUiSetHelpAsset)

            ENABLEHOOK(ScopeZoomUiUpdate)
            ENABLEHOOK(ScopeZoomUiSetHelpAsset)
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
