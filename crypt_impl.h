#if !defined(crypt) || !defined(CRYPT)
#  error "you should define the crypt algorithm name you used"
#endif

#define crypt_prefix_name(n)      crypt_prefix_name_(crypt, n)
#define crypt_prefix_name_(x, n)  crypt_prefix_name_r(x, n)
#define crypt_prefix_name_r(x, n) x##_##n

#define Lfuncname(n)      Lfuncname_(crypt, n)
#define Lfuncname_(x, n)  Lfuncname_r(x, n)
#define Lfuncname_r(x, n) L##x##_##n

#define crypt_t      crypt_prefix_name(t)
#define crypt_init   crypt_prefix_name(init)
#define crypt_update crypt_prefix_name(update)
#define crypt_finish crypt_prefix_name(finish)

#define Lcrypt_ctx_t       Lfuncname(ctx_t)
#define Lcrypt_do_update   Lfuncname(do_update)
#define Lcrypt_new_ctx     Lfuncname(new_ctx)

typedef struct Lcrypt_ctx_t {
  crypt_t ctx;
  crypt_cb_t cb;
} Lcrypt_ctx_t;

static int Lcrypt_do_update(lua_State *L, Lcrypt_ctx_t *m, int narg) {
  size_t len;
  const char *s = luaL_checklstring(L, narg, &len);
  if (m->cb.type == 'b') {
    int res;
    luaL_Buffer B;
    lua_pushnil(L);
    luaL_buffinit(L, &B);
    res = crypt_update(&m->ctx, s, len,
        Lcrypt_lbuf_writer, (void*)&B);
    luaL_pushresult(&B);
    return res ? 1 : 2;
  }
  return crypt_update(&m->ctx, s, len, m->cb.type == 'f' ?
      Lcrypt_file_writer : Lcrypt_cb_writer, (void*)m) ? -1 : 0;
}

static Lcrypt_ctx_t *Lcrypt_new_ctx(lua_State *L, int narg) {
  Lcrypt_ctx_t *m =
    (Lcrypt_ctx_t*)lua_newuserdata(L, sizeof(Lcrypt_ctx_t));
  Lcrypt_choose_cb(L, &m->cb, 2);
  return m;
}

#if defined(DEFINE_BIND_CLOSURE)

#define Lcrypt_update_helper Lfuncname(update_helper)
#define Lcrypt_func          Lfuncname(func)

static int Lcrypt_update_helper(lua_State *L) {
  Lcrypt_ctx_t *m =
    (Lcrypt_ctx_t*)lua_touserdata(L, lua_upvalueindex(2));
  int res;
  if (lua_isnoneornil(L, 1)) {
    if (m->cb.type == 'b') {
      luaL_Buffer B;
      lua_pushnil(L);
      luaL_buffinit(L, &B);
      res = crypt_finish(&m->ctx, Lcrypt_lbuf_writer, (void*)&B);
      luaL_pushresult(&B);
      return res ? 1 : 2;
    }
    else {
      if (crypt_finish(&m->ctx, m->cb.type == 'f' ?
          Lcrypt_file_writer : Lcrypt_cb_writer, (void*)m)) {
        lua_pushvalue(L, lua_upvalueindex(1));
        return 1;
      }
      return 0;
    }
  }
  res = Lcrypt_do_update(L, m, 1);
  if (res < 0) {
    lua_pushvalue(L, lua_upvalueindex(2));
    return 1;
  }
  return res;
}

static int Lcrypt_func(lua_State *L) {
  if (lua_isstring(L, 2)) {
    crypt_t m;
    luaL_Buffer B;
    int res;
    size_t len;
    const char *s = luaL_tolstring(L, 2, &len);
    lua_pushnil(L);
    luaL_buffinit(L, &B);
    crypt_init(&m, *luaL_optstring(L, 1, "encode") == 'd');
    res = crypt_update(&m, s, len, Lcrypt_lbuf_writer, (void*)&B)
       && crypt_finish(&m, Lcrypt_lbuf_writer, (void*)&B);
    luaL_pushresult(&B);
    return res ? 1 : 2;
  }
  else {
    Lcrypt_ctx_t *m = Lcrypt_new_ctx(L, 2);
    int is_decode = *luaL_optstring(L, 1, "encode") == 'd';
    lua_pushcclosure(L, Lcrypt_update_helper, 1);
    lua_pushvalue(L, -1);
    lua_setupvalue(L, -2, 1);
    crypt_init(&m->ctx, is_decode);
    return 1;
  }
}

#undef Lcrypt_update_helper
#undef Lcrypt_func


#elif defined(DEFINE_BIND_META)

#define CRYPT_TYPE      CRYPT_TYPE_(crypt)
#define CRYPT_TYPE_(x)  CRYPT_TYPE_R(x)
#define CRYPT_TYPE_R(x) #x " ctx"

#define crypt_setup_meta crypt_prefix_name(setup_meta)
#define crypt_libs       crypt_prefix_name(libs)

#define Lcrypt_tostring   Lfuncname(tostring)
#define Lcrypt_newindex   Lfuncname(newindex)
#define Lcrypt_new        Lfuncname(new)
#define Lcrypt_clone      Lfuncname(clone)
#define Lcrypt_reset      Lfuncname(reset)
#define Lcrypt_update     Lfuncname(update)
#define Lcrypt_finish     Lfuncname(finish)

static int Lcrypt_tostring(lua_State *L) {
  crypt_t *m = (crypt_t*)luaL_checkudata(L, 1, CRYPT_TYPE);
  lua_pushfstring(L, CRYPT_TYPE": %p", m);
  return 1;
}

static int Lcrypt_newindex(lua_State *L) {
  Lcrypt_ctx_t *m = (Lcrypt_ctx_t*)luaL_checkudata(L, 1, CRYPT_TYPE);
  if (!strcmp(luaL_checkstring(L, 2), "data"))
    Lcrypt_choose_cb(L, &m->cb, 3);
  else
    luaL_error(L, "only data field can be set.");
  return 0;
}

static int Lcrypt_new(lua_State *L) {
  int is_decode = *luaL_optstring(L, 1, "encode") == 'd';
  Lcrypt_ctx_t *m = Lcrypt_new_ctx(L, 2);
  luaL_setmetatable(L, CRYPT_TYPE);
  crypt_init(&m->ctx, is_decode);
  return 1;
}

static int Lcrypt_clone(lua_State *L) {
  Lcrypt_ctx_t *m = (Lcrypt_ctx_t*)luaL_checkudata(L, 1, CRYPT_TYPE);
  Lcrypt_ctx_t *newm = (Lcrypt_ctx_t*)lua_newuserdata(L, sizeof(Lcrypt_ctx_t));
  luaL_setmetatable(L, CRYPT_TYPE);
  memcpy(newm, m, sizeof(Lcrypt_ctx_t));
  return 1;
}

static int Lcrypt_reset(lua_State *L) {
  crypt_t *m = (crypt_t*)luaL_checkudata(L, 1, CRYPT_TYPE);
  crypt_init(m, *luaL_optstring(L, 2, "encode") == 'd');
  lua_settop(L, 1);
  return 1;
}

static int Lcrypt_update(lua_State *L) {
  Lcrypt_ctx_t *m = (Lcrypt_ctx_t*)luaL_checkudata(L, 1, CRYPT_TYPE);
  Lcrypt_do_update(L, m, 2);
  lua_settop(L, 1);
  return 1;
}

static int Lcrypt_finish(lua_State *L) {
  return 0;
}

static luaL_Reg crypt_libs[] = {
  { "__tostring", Lcrypt_tostring },
  { "new",        Lcrypt_new      },
  { "clone",      Lcrypt_clone    },
  { "reset",      Lcrypt_reset    },
  { "update",     Lcrypt_update   },
  { "finish",     Lcrypt_finish   },
  { NULL, NULL }
};

static void crypt_setup_meta(lua_State *L, const char *name) {
  luaL_newmetatable(L, CRYPT_TYPE);
  luaL_setfuncs(L, crypt_libs, 0);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, Lcrypt_newindex);
  lua_setfield(L, -2, "__newindex");
  lua_createtable(L, 0, 1);
  lua_pushcfunction(L, Lcrypt_new);
  lua_setfield(L, -2, "__call");
  lua_setmetatable(L, -2);
  lua_setfield(L, -2, name);
}

#undef CRYPT_TYPE
#undef CRYPT_TYPE_
#undef CRYPT_TYPE_R

#undef crypt_setup_meta
#undef crypt_libs

#undef Lcrypt_tostring
#undef Lcrypt_newindex
#undef Lcrypt_new
#undef Lcrypt_clone
#undef Lcrypt_reset
#undef Lcrypt_update
#undef Lcrypt_finish


#else
#error "you must define DEFINE_* macro"
#endif


#undef crypt_t
#undef crypt_init
#undef crypt_update
#undef crypt_finish

#undef Lcrypt_ctx_t
#undef Lcrypt_do_update
#undef Lcrypt_new_ctx

#undef Lfuncname
#undef Lfuncname_
#undef Lfuncname_r

#undef crypt_prefix_name
#undef crypt_prefix_name_
#undef crypt_prefix_name_r

#undef crypt
#undef CRYPT
