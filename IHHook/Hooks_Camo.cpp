#include "Hooks_Camo.h"
#include <cmath>
#include <cstdint>
#include <filesystem>//exename

#include "spdlog/spdlog.h"
#include "MinHook.h"
#include "HookMacros.h"

#include "IHHook.h"//DEBUGNOW
#include "hooks/mgsvtpp_func_typedefs.h"

namespace IHHook {
	namespace Hooks_Camo {

		static std::atomic    gCamoScore{0.0f};   // −1000..1000 after Update
		static std::atomic gSurfaceIdx{0};     // -1..82
		
		void __fastcall UpdatePlayerCamoHook(void* self) {
			// spdlog::debug(__func__);

			UpdatePlayerCamo(self);
			
			auto* s     = (uint8_t*)self;
			auto* owner = *(uint8_t**)(s + 0x38);
			if (!owner) return;

			// rIDX (R14D) — the engine’s slot index for this controller
			uint32_t idx = *(uint32_t*)(s + 0x58);

			// 2) Baseline camo (fVar14 that just got stored)
			float base = NAN;
			if (auto* blk60 = *(uint8_t**)(owner + 0x60)) {
				if (auto* table = *(float**)(blk60 + 0xD0)) {
					base = table[idx];
				}
			}
			gCamoScore.store(base, std::memory_order_relaxed);

		}//UpdatePlayerCamoHook*/

		void __fastcall SetSuitCamoHook(void* self, void* ctx) {
			// spdlog::debug(__func__);
			
			// capture "before"
			float* camoPtr = reinterpret_cast<float*>(reinterpret_cast<uint8_t*>(self) + 0x2FC);
			float before   = *camoPtr;

			// run the original
			SetSuitCamo(self, ctx);

			// capture "after"
			float after    = *camoPtr;

			// material/surface as written by the function (mirror)
			int*  surfMirPtr = reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(self) + 0x250);
			int   surfId     = *surfMirPtr;


			// suit bonus is an integer added as float (CVTDQ2PS). Round to nearest.
			/*int suitBonus = static_cast<int>(std::lround(after - before));
			
			spdlog::info("ExecSuitCorrect: self={} surfId={} bonus={} before={} after={}",
				self, surfId, suitBonus, before, after);*/

			gSurfaceIdx.store(surfId, std::memory_order_relaxed);

		}//SetSuitCamoHook*/

		void CreateHooks() {
			CREATE_HOOK(UpdatePlayerCamo)
			CREATE_HOOK(SetSuitCamo)

			ENABLEHOOK(UpdatePlayerCamo)
			ENABLEHOOK(SetSuitCamo)
		}//CreateHooks
		
		int l_GetCamoIndex(lua_State* L) {
			lua_pushnumber(L, gCamoScore.load());
			return 1;
		}

		int l_GetSurfaceMaterial(lua_State* L) {
			lua_pushnumber(L, gSurfaceIdx.load());
			return 1;
		}

		int CreateLibs(lua_State* L) {
			spdlog::debug(__func__);

			luaL_Reg libFuncs[] = {
				{ "GetCamoIndex", l_GetCamoIndex },
				{ "GetSurfaceMaterial", l_GetSurfaceMaterial },

				{ NULL, NULL }//GOTCHA: crashes without
			};
			luaI_openlib(L, "IhkCamo", libFuncs, 0);
			return 1;
		}//CreateLibs
	}//namespace Hooks_FOV
}//namespace IHHook