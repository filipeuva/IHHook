#pragma once
#include <optional>

#include "lua/lua.h"

namespace IHHook {
    namespace Hooks_Ui {
        void CreateHooks();
        int CreateLibs(lua_State* L);

        int l_PrintViewTree(lua_State* L);
    }//namespace Hooks_FOV
}//namespace IHHook