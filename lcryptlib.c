#include "base64.h"
/*#include "aes.h"*/
/*#include "des56.h"*/
/*#include "blowfish.h"*/

#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>

#include <string.h>

#define DEFINE_BIND_META
#ifndef DEFINE_BIND_META
#  define DEFINE_BIND_CLOSURE
#endif

typedef struct crypt_cb_t {
  int type; /* 'b' for buffer, 'f' for file, 'c' for callback */
  lua_State *L;
  FILE *fp;
} crypt_cb_t;

static int Lcrypt_lbuf_writer(void *ud, const char *s, size_t len) {
  luaL_addlstring((luaL_Buffer*)ud, s, len);
  return 1;
}

static int Lcrypt_file_writer(void *ud, const char *s, size_t len) {
  return fwrite(s, 1, len, ((crypt_cb_t*)ud)->fp) == 1;
}

static int Lcrypt_cb_writer(void *ud, const char *s, size_t len) {
  crypt_cb_t *m = (crypt_cb_t*)ud;
  lua_State *L = m->L;
  lua_rawgetp(L, LUA_REGISTRYINDEX, m);
  lua_pushlstring(L, s, len);
  return lua_pcall(L, 1, 0, 0) == LUA_OK;
}

static void Lcrypt_choose_cb(lua_State *L, crypt_cb_t *m, int narg) {
  m->L = L;
  switch (lua_type(L, narg)) {
    case LUA_TNONE:
    case LUA_TNIL:
      m->fp = NULL;
      m->type = 'b';
      break;
    case LUA_TUSERDATA:
      m->fp = luaL_checkudata(L, -1, LUA_FILEHANDLE);
      m->type = 'f';
      break;
    case LUA_TFUNCTION:
      lua_pushvalue(L, narg);
      lua_rawsetp(L, LUA_REGISTRYINDEX, m);
      m->type = 'c';
      break;
    default:
      lua_pushfstring(L, "file/function expected, got %s",
          luaL_typename(L, 2));
      luaL_argerror(L, 2, lua_tostring(L, -1));
  }
}


#define crypt b64
#define CRYPT B64
#include "crypt_impl.h"

#if 0
#define crypt aes
#define CRYPT AES
#include "crypt_impl.h"

#define crypt des56
#define CRYPT DES56
#include "crypt_impl.h"

#define crypt BF
#define CRYPT bf
#include "crypt_impl.h"
#endif


static luaL_Reg clib[] = {
#ifdef DEFINE_BIND_CLOSURE
    { "base64",     Lb64_func },
#if 0
    { "aes",        Laes_func },
    { "des56",      Ldes56_func },
    { "blowfish",   Lbf_func },
#endif
#endif
  { NULL, NULL }
};

LUALIB_API int luaopen_cryptlib(lua_State *L) {
  luaL_newlib(L, clib);
#ifdef DEFINE_BIND_META
  b64_setup_meta(L, "base64");
#if 0
  aes_setup_meta(L, "aes");
  des56_setup_meta(L, "des56");
  bf_setup_meta(L, "blowfish");
#endif
#endif
  return 1;
}
/*
 * xcc: flags+='-shared' output='hashlib.so' input='*.c'
 * cc: lua='lua52' flags+='-mdll -Id:/$lua/include -DLUA_BUILD_AS_DLL'
 * cc: libs+='d:/$lua/$lua.dll' output='hashlib.dll' input='*.c'
 */
