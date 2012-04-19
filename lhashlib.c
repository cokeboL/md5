#include "md5.h"
#include "sha1.h"

#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>

#include <string.h>

#define DEFINE_BIND_META
#ifndef DEFINE_BIND_META
#  define DEFINE_BIND_CLOSURE
#endif

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
#include "hash_impl.h"

#define hash sha1
#define HASH SHA1
#include "hash_impl.h"

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
#ifdef DEFINE_BIND_CLOSURE
  { "md5",      Lmd5_sum      },
  { "sha1",     Lsha1_sum     },
  { "md5hexa",  Lmd5_sumhexa  },
  { "sha1hexa", Lsha1_sumhexa },
#endif
  { "tohex", Ltohex },
  { "exor",  Lexor  },
  { NULL, NULL }
};

LUALIB_API int luaopen_hashlib(lua_State *L) {
  luaL_newlib(L, hlib);
#ifdef DEFINE_BIND_META
  md5_setup_meta(L, "md5");
  sha1_setup_meta(L, "sha1");
#endif
  return 1;
}
/*
 * xcc: flags+='-shared' output='hashlib.so' input='*.c'
 * cc: lua='lua52' flags+='-mdll -Id:/$lua/include -DLUA_BUILD_AS_DLL'
 * cc: libs+='d:/$lua/$lua.dll' output='hashlib.dll' input='*.c'
 */
