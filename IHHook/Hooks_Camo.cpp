#include "Hooks_Camo.h"
#include <stdexcept>
#include <cmath>
#include <cstdint>
#include <filesystem>//exename

#include "spdlog/spdlog.h"
#include "MinHook.h"
#include "HookMacros.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <MemoryUtils.h>

#include "IHHook.h"//DEBUGNOW
#include "hooks/mgsvtpp_func_typedefs.h"

namespace IHHook {
	namespace Hooks_Camo {

		static std::atomic    gCamoScore{0.0f};   // −1000..1000 after Update
		static std::atomic<uint16_t> gSurfaceIdx{0};     // 0..N (≈82)
		
		static inline bool JustPressed(int vk) { return (GetAsyncKeyState(vk) & 1) != 0; }
		
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

			// fallback: recompute it from the anim block if mirror is missing
			if (surfId == -1) {
				surfId = RecomputeSurfaceId(self);
			}

			// suit bonus is an integer added as float (CVTDQ2PS). Round to nearest.
			int suitBonus = static_cast<int>(std::lround(after - before));
			
			spdlog::info("ExecSuitCorrect: self={} surfId={} bonus={} before={} after={}",
				self, surfId, suitBonus, before, after);

			gSurfaceIdx.store(surfId, std::memory_order_relaxed);

		}//SetSuitCamoHook*/

		static int RecomputeSurfaceId(void* self) {
			spdlog::debug(__func__);
			
			auto s8   = reinterpret_cast<uint8_t*>(self);
			auto p60  = *reinterpret_cast<uint8_t**>(s8 + 0x60);
			if (!p60) return -1;

			auto p48   = *reinterpret_cast<uint8_t**>(p60 + 0x48);
			if (!p48)  return -1;
			auto p18   = *reinterpret_cast<uint8_t**>(p48 + 0x18);
			if (!p18)  return -1;
			auto blk   = *reinterpret_cast<uint8_t**>(p18 + 0x48);
			if (!blk)  return -1;

			int frame        = *reinterpret_cast<int*>(s8 + 0x7C);
			int baseFrame    = *reinterpret_cast<int*>(blk + 0x14);
			int idx          = frame - baseFrame;
			if (idx < 0)     return -1;

			auto matBase     = *reinterpret_cast<uint8_t**>(blk + 0x08);
			if (!matBase)    return -1;

			uint8_t* rec     = matBase + static_cast<size_t>(idx) * 0xE0;
			uint8_t  flags   = *(rec + 0x40);
			if ((flags & 0x01) == 0) return -1;

			int surfId       = *reinterpret_cast<int*>(rec + 0x44);
			return surfId;
		}

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