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

#define DEFINE_HASH_UPDATE(hash, HASH) \
  static int hash##_update_helper(lua_State *L) {             \
    hash##_t *m =                                             \
    (hash##_t*)lua_touserdata(L, lua_upvalueindex(2));        \
    if (lua_isnoneornil(L, 1)) {                              \
      char buff[HASH##_HASHSIZE];                             \
      hash##_finish(m, buff);                                 \
      hash##_init(m);                                         \
      if (lua_toboolean(L, lua_upvalueindex(3)))              \
      return tohex(L, buff, HASH##_HASHSIZE);                 \
      lua_pushlstring(L, buff, HASH##_HASHSIZE);              \
    }                                                         \
    else {                                                    \
      size_t len;                                             \
      const char *message = luaL_checklstring(L, 1, &len);    \
      hash##_update(m, message, len);                         \
      lua_pushvalue(L, lua_upvalueindex(1));                  \
    }                                                         \
    return 1;                                                 \
  }

#define DEFINE_HASH_FUNC(hash, HASH) \
  static int hash##_func(lua_State *L, int needhexa) {        \
    if (lua_isnoneornil(L, 1)) {                              \
      hash##_t *m;                                            \
      lua_pushnil(L);                                         \
      m = (hash##_t*)lua_newuserdata(L, sizeof(hash##_t));    \
      lua_pushboolean(L, needhexa);                           \
      lua_pushcclosure(L, hash##_update_helper, 3);           \
      lua_pushvalue(L, -1);                                   \
      lua_setupvalue(L, -2, 1);                               \
      hash##_init(m);                                         \
    }                                                         \
    else {                                                    \
      size_t len;                                             \
      const char *message = luaL_checklstring(L, 1, &len);    \
      char buff[HASH##_HASHSIZE];                             \
      hash(message, len, buff);                               \
      if (needhexa)                                           \
      return tohex(L, buff, HASH##_HASHSIZE);                 \
      lua_pushlstring(L, buff, HASH##_HASHSIZE);              \
    }                                                         \
    return 1;                                                 \
  }

DEFINE_HASH_UPDATE(md5, MD5)
DEFINE_HASH_FUNC(md5, MD5)
DEFINE_HASH_UPDATE(sha1, SHA1)
DEFINE_HASH_FUNC(sha1, SHA1)

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
/* xcc: flags+='-shared' output='hashlib.so' input='*.c'
 * cc: lua='lua52' flags+='-mdll -Id:/$lua/include -DLUA_BUILD_AS_DLL'
 * cc: libs+='d:/$lua/$lua.dll' output='hashlib.dll' input='*.c'
 */
