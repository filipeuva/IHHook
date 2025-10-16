#pragma once
#include "lua/lua.h"

namespace IHHook {
    namespace Hooks_Camo {
        void CreateHooks();
        int CreateLibs(lua_State* L);

        int l_GetCamoIndex(lua_State* L);
        int l_GetSurfaceMaterial(lua_State* L);
        int l_GetTick(lua_State* L);

        static int RecomputeSurfaceId(void* self);
        //DELETEME
        
    }//namespace Hooks_FOV
}//namespace IHHook