#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>


#include "md5.h"
#include "sha1.h"

#define MD5_TYPE "md5 context"
#define SHA1_TYPE "sha1 context"

static int tohex(lua_State *L, const char *s, size_t len) {
  static const char *hexvalue = "0123456789abcdef";
  size_t i;
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  for (i = 0; i < len; ++i) {
    luaL_addchar(&b, hexvalue[(s[i]>>4)&0xF]);
    luaL_addchar(&b, hexvalue[s[i]&0xF]);
  }
  luaL_pushresult(&b);
  return 1;
}

#define hash md5
#define HASH MD5
#define DEFINE_BIND
#include "hash_impl.h"

#define hash sha1
#define HASH SHA1
#define DEFINE_BIND
#include "hash_impl.h"

static int Lmd5(lua_State *L) { return md5_func(L, 0); }
static int Lmd5hexa(lua_State *L) { return md5_func(L, 1); }
static int Lsha1(lua_State *L) { return sha1_func(L, 0); }
static int Lsha1hexa(lua_State *L) { return sha1_func(L, 1); }


static int Ltohex(lua_State *L) {
  size_t len;
  const char *s = luaL_checklstring(L, 1, &len);
  return tohex(L, s, len);
}


static int Lexor (lua_State *L) {
  size_t l1, l2;
  const char *s1 = luaL_checklstring(L, 1, &l1);
  const char *s2 = luaL_checklstring(L, 2, &l2);
  luaL_Buffer b;
  luaL_argcheck( L, l1 == l2, 2, "lengths must be equal" );
  luaL_buffinit(L, &b);
  while (l1--) luaL_addchar(&b, (*s1++)^(*s2++));
  luaL_pushresult(&b);
  return 1;
}


static luaL_Reg hlib[] = {
  { "md5",      Lmd5      },
  { "sha1",     Lsha1     },
  { "md5hexa",  Lmd5hexa  },
  { "sha1hexa", Lsha1hexa },
  { "tohex",    Ltohex    },
  { "exor",     Lexor     },
  { NULL, NULL }
};


LUALIB_API int luaopen_hashlib(lua_State *L) {
  luaL_newlib(L, hlib);
  return 1;
}
/* xcc: lua='lua52' flags+='-mdll -Id:/$lua/include -DLUA_BUILD_AS_DLL'
 * xcc: libs+='d:/$lua/$lua.dll' output='hashlib.dll' input='*.c'
 * cc: flags+='-shared' output='hashlib.so' input='*.c'
 */
