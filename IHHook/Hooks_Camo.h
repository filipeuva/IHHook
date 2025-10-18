#pragma once
#include "lua/lua.h"

namespace IHHook {
    namespace Hooks_Camo {
        void CreateHooks();
        int CreateLibs(lua_State* L);

        int l_GetCamoIndex(lua_State* L);
        int l_GetSurfaceMaterial(lua_State* L);
    }//namespace Hooks_FOV
}//namespace IHHook