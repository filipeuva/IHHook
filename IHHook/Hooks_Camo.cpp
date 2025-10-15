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

		static ulonglong gTick=0;
		static int    detectFrames = 300;        // ~5s @60fps
		static int    activeIdx    = -1;
		static float  prev[64]     = {};         // change detector

		
		static inline bool JustPressed(int vk) { return (GetAsyncKeyState(vk) & 1) != 0; }
		
		/**
		 * hook_update_fov_lerp - Change the target fov
		 * @thisptr:	Struct containing fov data
		 *
		 * Check the unmodified focal length and change to the appropriate new one
		 */
		void __fastcall UpdatePlayerCamoHook(void* self) {
			spdlog::debug(__func__);

			UpdatePlayerCamo(self);

			auto* s      = (uint8_t*)self;
			auto* owner  = *reinterpret_cast<uint8_t**>(s + 0x38);
			if (!owner) return;

			// Engine-mirrored index (the one used in this controller)
			uint32_t idx = *reinterpret_cast<uint32_t*>(s + 0x58);

			// Correct base chain for the camo score table
			auto* blk        = *reinterpret_cast<uint8_t**>(owner + 0x60);
			auto* scoreTable = blk ? *reinterpret_cast<float**>(blk + 0xD0) : nullptr;

			// Surface index mirror from this object
			uint16_t surf = *reinterpret_cast<uint16_t*>(s + 0x5C);

			if (scoreTable) gCamoScore.store(scoreTable[idx], std::memory_order_relaxed);
			gSurfaceIdx.store(surf, std::memory_order_relaxed);
			
		}//UpdatePlayerCamoHook

		void CreateHooks() {
			CREATE_HOOK(UpdatePlayerCamo)
			ENABLEHOOK(UpdatePlayerCamo)
		}//CreateHooks
		
		int l_GetCamoIndex(lua_State* L) {
			lua_pushnumber(L, gCamoScore.load());
			return 1;
		}

		int l_GetSurfaceMaterial(lua_State* L) {
			lua_pushnumber(L, gSurfaceIdx.load());
			return 1;
		}

		int l_GetTick(lua_State* L) {
			lua_pushnumber(L, gTick);
			return 1;
		}

		int CreateLibs(lua_State* L) {
			spdlog::debug(__func__);

			luaL_Reg libFuncs[] = {
				{ "GetCamoIndex", l_GetCamoIndex },
				{ "GetSurfaceMaterial", l_GetSurfaceMaterial },
				{ "GetTick", l_GetTick },

				{ NULL, NULL }//GOTCHA: crashes without
			};
			luaI_openlib(L, "IhkCamo", libFuncs, 0);
			return 1;
		}//CreateLibs
	}//namespace Hooks_FOV
}//namespace IHHook