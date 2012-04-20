#if !defined(hash) || !defined(HASH)
#  error "you should define the hash algorithm name you used"
#endif

#define HASH_PREFIX_NAME(N)      HASH_PREFIX_NAME_(HASH, N)
#define HASH_PREFIX_NAME_(X, N)  HASH_PREFIX_NAME_R(X, N)
#define HASH_PREFIX_NAME_R(X, N) X##_##N

#define hash_prefix_name(n)      hash_prefix_name_(hash, n)
#define hash_prefix_name_(x, n)  hash_prefix_name_r(x, n)
#define hash_prefix_name_r(x, n) x##_##n

#define Lfuncname(n)      Lfuncname_(hash, n)
#define Lfuncname_(x, n)  Lfuncname_r(x, n)
#define Lfuncname_r(x, n) L##x##_##n

#define HASH_HASHSIZE  HASH_PREFIX_NAME(HASHSIZE)
#define HASH_BLOCKSIZE HASH_PREFIX_NAME(BLOCKSIZE)

#define hash_t      hash_prefix_name(t)
#define hash_init   hash_prefix_name(init)
#define hash_update hash_prefix_name(update)
#define hash_finish hash_prefix_name(finish)


#ifdef DEFINE_API_IMPL

void hash_init(hash_t *m) {
  init_digest(m->d);
  m->len = m->bufflen = 0;
}

void hash_update(hash_t *m, const char *message, size_t len) {
  WORD32 wbuff[MLEN];
  if (m->bufflen != 0) {
    int numbytes = m->bufflen+len < HASH_BLOCKSIZE ? len :
      HASH_BLOCKSIZE - m->bufflen;
    memcpy(&m->buff[m->bufflen], message, numbytes);
    if ((m->bufflen += numbytes) < HASH_BLOCKSIZE)
      return;
    bytestoword32(wbuff, m->buff);
    digest(wbuff, m->d);
    m->len += HASH_BLOCKSIZE;
    message += numbytes;
    len -= numbytes;
  }
  while (len >= HASH_BLOCKSIZE) {
    bytestoword32(wbuff, message);
    digest(wbuff, m->d);
    m->len += HASH_BLOCKSIZE;
    message += HASH_BLOCKSIZE;
    len -= HASH_BLOCKSIZE;
  }
  memcpy(m->buff, message, len);
  m->bufflen = len;
}

void hash_finish(hash_t *m, char output[HASH_HASHSIZE]) {
  WORD32 wbuff[MLEN];
  m->len += m->bufflen;
  m->buff[m->bufflen++] = '\x80';
  memset(&m->buff[m->bufflen], 0, HASH_BLOCKSIZE-m->bufflen);
  bytestoword32(wbuff, m->buff);
  if (m->bufflen > (HASH_BLOCKSIZE-8)) {
    digest(wbuff, m->d);
    memset(wbuff, 0, HASH_BLOCKSIZE);
  }
  wbuff[HASH_BLOCKSIZE/4-2] = (m->len>>(WSIZE-3)) & 0x7;
  wbuff[HASH_BLOCKSIZE/4-1] = (m->len<<3) & MASK;
  digest(wbuff, m->d);
  word32tobytes(m->d, output);
}

void hash(const char *message, size_t len, char output[HASH_HASHSIZE]) {
  hash_t m;
  hash_init(&m);
  hash_update(&m, message, len);
  hash_finish(&m, output);
}


#elif defined(DEFINE_BIND_CLOSURE)

#define Lhash_update_helper Lfuncname(update_helper)
#define Lhash_impl          Lfuncname(impl)
#define Lhash_sum           Lfuncname(sum)
#define Lhash_sumhexa       Lfuncname(sumhexa)

static int Lhash_update_helper(lua_State *L) {
  hash_t *m =
    (hash_t*)lua_touserdata(L, lua_upvalueindex(2));
  if (lua_isnoneornil(L, 1)) {
    char buff[HASH_HASHSIZE];
    hash_finish(m, buff);
    hash_init(m);
    if (lua_toboolean(L, lua_upvalueindex(3)))
      return tohex(L, buff, HASH_HASHSIZE);
    lua_pushlstring(L, buff, HASH_HASHSIZE);
  }
  else {
    size_t len;
    const char *message = luaL_checklstring(L, 1, &len);
    hash_update(m, message, len);
    lua_pushvalue(L, lua_upvalueindex(1));
  }
  return 1;
}

static int Lhash_impl(lua_State *L, int needhexa) {
  if (lua_isnoneornil(L, 1)) {
    hash_t *m;
    lua_pushnil(L);
    m = (hash_t*)lua_newuserdata(L, sizeof(hash_t));
    lua_pushboolean(L, needhexa);
    lua_pushcclosure(L, Lhash_update_helper, 3);
    lua_pushvalue(L, -1);
    lua_setupvalue(L, -2, 1);
    hash_init(m);
  }
  else {
    size_t len;
    const char *message = luaL_checklstring(L, 1, &len);
    char buff[HASH_HASHSIZE];
    hash(message, len, buff);
    if (needhexa)
      return tohex(L, buff, HASH_HASHSIZE);
    lua_pushlstring(L, buff, HASH_HASHSIZE);
  }
  return 1;
}

static int Lhash_sum(lua_State *L) { return Lhash_impl(L, 0); }
static int Lhash_sumhexa(lua_State *L) { return Lhash_impl(L, 1); }

#undef Lhash_update_helper
#undef Lhash_impl
#undef Lhash_sum
#undef Lhash_sumhexa


#elif defined(DEFINE_BIND_META)

#define HASH_TYPE      HASH_TYPE_(hash)
#define HASH_TYPE_(x)  HASH_TYPE_R(x)
#define HASH_TYPE_R(x) #x " context"

#define hash_setup_meta hash_prefix_name(setup_meta)
#define hash_libs       hash_prefix_name(libs)

#define Lhash_tostring   Lfuncname(tostring)
#define Lhash_new        Lfuncname(new)
#define Lhash_digest     Lfuncname(digest)
#define Lhash_hexadigest Lfuncname(hexadigest)
#define Lhash_clone      Lfuncname(clone)
#define Lhash_reset      Lfuncname(reset)
#define Lhash_update     Lfuncname(update)

static int Lhash_tostring(lua_State *L) {
  hash_t *m = (hash_t*)luaL_checkudata(L, 1, HASH_TYPE);
  lua_pushfstring(L, HASH_TYPE": %p", m);
  return 1;
}

static int Lhash_new(lua_State *L) {
  hash_t *m = (hash_t*)lua_newuserdata(L, sizeof(hash_t));
  luaL_setmetatable(L, HASH_TYPE);
  hash_init(m);
  if (lua_isstring(L, -2)) {
      size_t len;
      const char *s = lua_tolstring(L, -2, &len);
      hash_update(m, s, len);
  }
  return 1;
}

static int Lhash_digest(lua_State *L) {
  hash_t *m = (hash_t*)luaL_checkudata(L, 1, HASH_TYPE);
  char buff[HASH_HASHSIZE];
  hash_finish(m, buff);
  lua_pushlstring(L, buff, HASH_HASHSIZE);
  hash_init(m);
  return 1;
}

static int Lhash_hexadigest(lua_State *L) {
  hash_t *m = (hash_t*)luaL_checkudata(L, 1, HASH_TYPE);
  char buff[HASH_HASHSIZE];
  hash_finish(m, buff);
  hash_init(m);
  return tohex(L, buff, HASH_HASHSIZE);
}

static int Lhash_clone(lua_State *L) {
  hash_t *m = (hash_t*)luaL_checkudata(L, 1, HASH_TYPE);
  hash_t *newm = (hash_t*)lua_newuserdata(L, sizeof(hash_t));
  luaL_setmetatable(L, HASH_TYPE);
  memcpy(newm, m, sizeof(hash_t));
  return 1;
}

static int Lhash_reset(lua_State *L) {
  hash_t *m = (hash_t*)luaL_checkudata(L, 1, HASH_TYPE);
  hash_init(m);
  lua_settop(L, 1);
  return 1;
}

static int Lhash_update(lua_State *L) {
  hash_t *m = (hash_t*)luaL_checkudata(L, 1, HASH_TYPE);
  size_t len;
  const char *s = luaL_checklstring(L, 2, &len);
  hash_update(m, s, len);
  lua_settop(L, 1);
  return 1;
}

static luaL_Reg hash_libs[] = {
  { "__tostring", Lhash_tostring   },
  { "new",        Lhash_new        },
  { "digest",     Lhash_digest     },
  { "hexadigest", Lhash_hexadigest },
  { "clone",      Lhash_clone      },
  { "reset",      Lhash_reset      },
  { "update",     Lhash_update     },
  { NULL, NULL }
};

static void hash_setup_meta(lua_State *L, const char *name) {
  luaL_newmetatable(L, HASH_TYPE);
  luaL_setfuncs(L, hash_libs, 0);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  lua_createtable(L, 0, 1);
  lua_pushcfunction(L, Lhash_new);
  lua_setfield(L, -2, "__call");
  lua_setmetatable(L, -2);
  lua_setfield(L, -2, name);
}

#undef HASH_TYPE
#undef HASH_TYPE_
#undef HASH_TYPE_R

#undef hash_setup_meta
#undef hash_libs

#undef Lhash_tostring
#undef Lhash_new
#undef Lhash_digest
#undef Lhash_hexadigest
#undef Lhash_clone
#undef Lhash_reset
#undef Lhash_update


#else
#error "you must define DEFINE_* macro"
#endif


#undef HASH_HASHSIZE
#undef HASH_BLOCKSIZE

#undef hash_t
#undef hash_init
#undef hash_update
#undef hash_finish

#undef Lfuncname
#undef Lfuncname_
#undef Lfuncname_r

#undef HASH_PREFIX_NAME
#undef HASH_PREFIX_NAME_
#undef HASH_PREFIX_NAME_R

#undef hash_prefix_name
#undef hash_prefix_name_
#undef hash_prefix_name_r

#undef hash
#undef HASH
