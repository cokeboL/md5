
#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>


#include "base64.h"
/*#include "aes.h"*/
/*#include "des56.h"*/
/*#include "blowfish.h"*/


static luaL_Reg clib[] = {
  /*{ "b64encode", Lb64encode },*/
  /*{ "b64decode", Lb64decode },*/
  { NULL, NULL }
};

LUALIB_API int luaopen_cryptlib(lua_State *L) {
  luaL_newlib(L, clib);
  return 1;
}
/* cc: flags+='-shared' output='hashlib.so' input='*.c' */
