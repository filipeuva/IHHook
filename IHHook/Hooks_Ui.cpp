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
        // -------- utils
        static inline uint8_t* get_text_section(HMODULE m, size_t& outSize)
        {
            auto dos = (IMAGE_DOS_HEADER*)m;
            auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)m + dos->e_lfanew);
            auto sh = IMAGE_FIRST_SECTION(nt);
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++)
            {
                char name[9]{};
                memcpy(name, sh[i].Name, 8);
                if (strcmp(name, ".text") == 0)
                {
                    outSize = sh[i].Misc.VirtualSize ? sh[i].Misc.VirtualSize : sh[i].SizeOfRawData;
                    return (uint8_t*)m + sh[i].VirtualAddress; // mapped VA
                }
            }
            outSize = 0;
            return nullptr;
        }

        static inline void* aob_find(uint8_t* base, size_t size, const char* pat)
        {
            std::vector<int> bytes;
            bytes.reserve(512);
            for (const char* p = pat; *p;)
            {
                while (*p == ' ') ++p;
                if (!*p) break;
                if (p[0] == '?' && p[1] == '?')
                {
                    bytes.push_back(-1);
                    p += 2;
                }
                else
                {
                    unsigned v = 0;
                    sscanf(p, "%2x", &v);
                    bytes.push_back((int)v);
                    p += 2;
                }
                while (*p == ' ') ++p;
            }
            const size_t n = bytes.size();
            for (size_t i = 0; i + n <= size; i++)
            {
                bool ok = true;
                for (size_t j = 0; j < n; j++)
                {
                    int b = bytes[j];
                    if (b >= 0 && base[i + j] != (uint8_t)b)
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok) return base + i;
            }
            return nullptr;
        }

        template <class T=void*>
        static inline T RP(void* p, size_t off) { return *(T*)((uint8_t*)p + off); }

        static inline void** VT(void* obj) { return obj ? *(void***)obj : nullptr; }

        // -------- modes
        enum OverrideMode : int { MODE_OFF = 0, MODE_ONLY_WHEN_NOT_ADS = 1, MODE_ALWAYS = 2 };

        // -------- state
        struct ZoomRefs
        {
            void* label = nullptr; // B: +0x198, fallback A: +0x178
            void* main = nullptr; // B: +0x1A0, fallback A: +0x180
            void* shad = nullptr; // B: +0x1A8, fallback A: +0x188
        };

        static std::atomic<ZoomRefs> g_refs;
        static std::atomic<int> g_ads{0};
        static std::atomic<int> g_mode{MODE_ALWAYS};
        static char g_label[32] = "Hello";
        static char g_value[64] = "World";

        // ---- engine types
        using Fn_SubmitText        = void(*)(void* draw, void* node, void* ctx, const char* txt, int a5);

        // ---- originals
        static Fn_SubmitText        oSubmitText=nullptr;

        
        // -------- helpers
        static inline bool allow_override()
        {
            int m = g_mode.load(std::memory_order_relaxed);
            if (m == MODE_ALWAYS) return true;
            if (m == MODE_ONLY_WHEN_NOT_ADS) return g_ads.load(std::memory_order_relaxed) == 0;
            return false;
        }

        // Hooks 
        void __fastcall ScopeZoomUiUpdateHook(void* self)
        {
            spdlog::debug(__func__);

            ScopeZoomUiUpdate(self);

            void* st = RP(self, 0x50);
            if (st)
            {
                uint8_t flags = *(uint8_t*)((uint8_t*)st + 0x328);
                g_ads.store((flags & 1) ? 1 : 0, std::memory_order_relaxed);
            }
        } //ScopeZoomUiUpdateHook

        // void __fastcall ScopeZoomUiUpdateSightHook(void* self)
        // {
        //     spdlog::debug(__func__);
        //
        //     ScopeZoomUiUpdateSight(self);
        //
        //
        // } //ScopeZoomUiUpdateSightHook

        void __fastcall ScopeZoomUiUpdateScopeLengthHook(void* self)
        {
            spdlog::debug(__func__);

            // steal SubmitText on first pass only, from the live draw instance
            if (!oSubmitText)
            {
                void* mgr48 = RP(self, 0x48);
                void* draw = mgr48 ? RP<void*>(mgr48, 0x20) : nullptr;
                if (draw)
                {
                    void** v = VT(draw);
                    if (v)
                    {
                        auto p = (Fn_SubmitText)v[0x708 / 8];
                        if (p)
                        {
                            MH_CreateHook(
                                (LPVOID)p, (LPVOID)+[](void* draw, void* node, void* ctx, const char* txt, int a5)
                                {
                                    spdlog::debug("");
                                    ZoomRefs z = g_refs.load(std::memory_order_acquire);
                                    spdlog::info("SubmitText Hook: text=\"{}\"", txt);
                                    if (allow_override())
                                    {
                                        if (node == z.label || node == z.main || node == z.shad) spdlog::debug("Should override!");
                                        if (node == z.label) txt = g_label;
                                        else if (node == z.main || node == z.shad) txt = g_value;

                                        if (std::string (txt) == "ZOOM")
                                        {
                                            spdlog::info("SubmitText Hook: z.label=\"{}\"", txt);
                                            txt = g_label;
                                        } else if (std::string(txt) == "X4.0")
                                        {
                                            spdlog::debug("Should override!");
                                            txt = g_value;
                                        }
                                    } else
                                    {
                                        spdlog::debug("Not allowed to override");
                                    }
                                    oSubmitText(draw, node, ctx, txt, a5);
                                }, (LPVOID*)&oSubmitText);
                            MH_EnableHook((LPVOID)p);
                        }
                    }
                }
            }
            
            ScopeZoomUiUpdateScopeLength(self);
        } //ScopeZoomUiUpdateScopeLength

        void __fastcall ScopeZoomUiSetHelpAssetHook(void* self, void* layoutA, void* layoutB)
        {
            spdlog::debug(__func__);

            ScopeZoomUiSetHelpAsset(self, layoutA, layoutB);

            ZoomRefs z{};
            // prefer B-layout nodes
            z.label = RP(self, 0x198);
            z.main = RP(self, 0x1A0);
            z.shad = RP(self, 0x1A8);
            if (!z.main)
            {
                z.label = RP(self, 0x178);
                z.main = RP(self, 0x180);
                z.shad = RP(self, 0x188);
            }
            g_refs.store(z, std::memory_order_release);
        } //ScopeZoomUiSetHelpAssetHook

        void CreateHooks()
        {
            CREATE_HOOK(ScopeZoomUiUpdate)
            // CREATE_HOOK(ScopeZoomUiUpdateSight)
            CREATE_HOOK(ScopeZoomUiUpdateScopeLength)
            CREATE_HOOK(ScopeZoomUiSetHelpAsset)

            ENABLEHOOK(ScopeZoomUiUpdate)
            // ENABLEHOOK(ScopeZoomUiUpdateSight)
            ENABLEHOOK(ScopeZoomUiUpdateScopeLength)
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
