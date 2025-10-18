#include "Hooks_Ui.h"
#include <filesystem>//exename

#include "spdlog/spdlog.h"
#include "MinHook.h"
#include "HookMacros.h"

#include "IHHook.h"//DEBUGNOW
#include "hooks/mgsvtpp_func_typedefs.h"

namespace IHHook {
	namespace Hooks_Ui {

		void __fastcall OnScopeZoomUiHook(void* self, void* layoutA, void* layoutB) {
			spdlog::debug(__func__);

			OnScopeZoomUi(self, layoutA, layoutB);
			
			

		}//OnScopeZoomUiHook

		

		void CreateHooks() {
			CREATE_HOOK(OnScopeZoomUi)

			ENABLEHOOK(OnScopeZoomUi)
		}//CreateHooks
		

		int CreateLibs(lua_State* L) {
			spdlog::debug(__func__);

			luaL_Reg libFuncs[] = {

				{ NULL, NULL }//GOTCHA: crashes without
			};
			luaI_openlib(L, "IhkUi", libFuncs, 0);
			return 1;
		}//CreateLibs
	}//namespace Hooks_FOV
}//namespace IHHook