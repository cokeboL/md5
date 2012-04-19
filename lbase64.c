#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>

#include <stddef.h>
#include <string.h>


static void b64_encode_block(const char *src, char *dst) {
    static const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789+/";
    *dst++ = table[(src[0]>>2          )&0x3F];
    *dst++ = table[(src[0]<<4|src[1]>>4)&0x3F];
    *dst++ = table[(src[1]<<2|src[2]>>6)&0x3F];
    *dst++ = table[(src[2]             )&0x3F];
}


static void base64_encode(luaL_Buffer *B, const char *src, size_t len) {
    char buff[4];
    while (len >= 3) {
        b64_encode_block(src, buff);
        luaL_addlstring(B, buff, 4);
        src += 3;
        len -= 3;
    }
    if (len != 0) {
        char srcbuff[3] = {0};
        switch (len) {
        case 2: srcbuff[1] = src[1];
        case 1: srcbuff[0] = src[0];
        }
        b64_encode_block(srcbuff, buff);
        switch (len) {
        case 1: buff[2] = '=';
        case 2: buff[3] = '=';
        }
        luaL_addlstring(B, buff, 4);
    }
}


static int decode_one(char ch, int mask, int *mm) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    switch (ch) {
    case '+': return 62;
    case '/': return 63;
    }
    *mm |= mask;
    return 0;
}

#ifdef B64_FAST_DECODE
static int fast_decode_one(char ch, int mask, int *mm) {
    static int initialized = 0;
    static unsigned char table[256] = {0};
    if (!initialized) {
        int i;
        for (i = 0; i < 256; ++i) {
                 if (i >= 'A' && i <= 'Z') table[i] = i - 'A';
            else if (i >= 'a' && i <= 'z') table[i] = i - 'a' + 26;
            else if (i >= '0' && i <= '9') table[i] = i - '0' + 52;
            else switch (i) {
                case '+': table[i] = 62; continue;
                case '/': table[i] = 63; continue;
            }
            table[i] = -1;
        }
        initialized = 1;
    }
    else {
        int digit = table[ch];
        if (digit == -1) {
            *mm |= mask;
            return 0;
        }
        return digit;
    }
}
#define decode_one fast_decode_one
#endif

static int b64_decode_block(const char *src, char *dst) {
    int mask = 0;
    int a = decode_one(src[0], 8, &mask), b = decode_one(src[1], 4, &mask),
        c = decode_one(src[2], 2, &mask), d = decode_one(src[3], 1, &mask);
    *dst++ = (a<<2|b>>4) & 0xFF;
    *dst++ = (b<<4|c>>2) & 0xFF;
    *dst++ = (c<<6|d   ) & 0xFF;
    return mask;
}

static int base64_decode(luaL_Buffer *B, const char *src, size_t len) {
    int mask = 0;
    char buff[3];
    while (len >= 4 && (mask = b64_decode_block(src, buff)) == 0) {
        luaL_addlstring(B, buff, 3);
        src += 4;
        len -= 4;
    }
    if (mask == 0) {
        int mask = 0;
        switch (len) {
        case 0: return 1;
        case 3: decode_one(src[2], 4, &mask);
        case 2: decode_one(src[1], 2, &mask);
        case 1: decode_one(src[0], 1, &mask);
        }
        return mask == (4|2|1); /* must invalid character, follow Python's */
    }
    if ((mask & (8|4)) != 0) return 1; /* follow Python's */
    luaL_addchar(B, buff[0]);
    if (src[3] == '=' && (mask & 2) == 0) {
        luaL_addchar(B, buff[1]);
        mask = 0;
    }
    return src[2] == '=' || mask == 0;
}

static int Lencode(lua_State *L) {
    size_t len;
    const char *s = luaL_checklstring(L, 1, &len);
    luaL_Buffer buff;
    luaL_buffinit(L, &buff);
    base64_encode(&buff, s, len);
    luaL_pushresult(&buff);
    return 1;
}

static int Ldecode(lua_State *L) {
    size_t len;
    const char *s = luaL_checklstring(L, 1, &len);
    luaL_Buffer buff;
    int res;
    luaL_buffinit(L, &buff);
    res = base64_decode(&buff, s, len);
    luaL_pushresult(&buff);
    if (res) return 1;
    lua_pushnil(L);
    lua_pushstring(L, "invalid padding");
    lua_pushvalue(L, -3);
    return 3;
}

static luaL_Reg b64lib[] = {
    { "encode", Lencode },
    { "decode", Ldecode },
    { NULL, NULL }
};

LUALIB_API int luaopen_base64(lua_State *L) {
    luaL_newlib(L, b64lib);
    return 1;
}

/* cc: flags+='-pedantic -Wall -shared' output='base64.so' */
