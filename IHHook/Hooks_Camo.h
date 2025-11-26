#pragma once
#include "lua/lua.h"

namespace IHHook {
    namespace Hooks_Camo {
        void CreateHooks();
        int CreateLibs(lua_State* L);

        extern std::atomic<float> gCamoScore;   // −1000..1000 after Update
        extern std::atomic<int>   gSurfaceIdx;  // -1..82

        int l_GetCamoIndex(lua_State* L);
        int l_GetSurfaceMaterial(lua_State* L);
    }//namespace Hooks_FOV
}//namespace IHHook