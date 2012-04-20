#include "base64.h"

#include <string.h>

static int b64_encode_block(const char *src, char *dst) {
  const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                      "abcdefghijklmnopqrstuvwxyz"
                      "0123456789+/";
  *dst++ = table[(src[0]>>2          )&0x3F];
  *dst++ = table[(src[0]<<4|src[1]>>4)&0x3F];
  *dst++ = table[(src[1]<<2|src[2]>>6)&0x3F];
  *dst++ = table[(src[2]             )&0x3F];
  return 0;
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


void b64_init(b64_t *m, int is_decode) {
  m->bufflen = m->mask = 0;
  m->is_decode = is_decode;
}

int b64_update(b64_t *m, const char *s, size_t len, b64_Writer w, void *ud) {
  size_t insize;
  int (*worker)(const char*, char*);
  char buff[4];
  if (m->mask) return 1;
  if (m->is_decode)
    insize = B64_ENCSIZE, worker = b64_encode_block;
  else
    insize = B64_DECSIZE, worker = b64_decode_block;
  if (m->bufflen != 0) {
    int numbytes = m->bufflen+len <= insize ? len :
      insize - m->bufflen;
    memcpy(&m->buff[m->bufflen], s, numbytes);
    if ((m->bufflen += numbytes) < insize ||
        (m->mask = worker(m->buff, buff)) != 0)
      return 1;
    if (!w(ud, buff, insize)) return 0;
    s += insize;
    len -= insize;
  }
  while (len >= insize) {
    if ((m->mask = worker(s, buff)) != 0) {
      m->bufflen = len>=insize ? insize : len;
      memcpy(m->buff, s, m->bufflen);
      return 1;
    }
    if (!w(ud, buff, insize)) return 0;
    s += insize;
    len -= insize;
  }
  memcpy(m->buff, s, len);
  m->bufflen = len;
  return 1;
}

int b64_finish(b64_t *m, b64_Writer w, void *ud) {
  char buff[4];
  if (m->is_decode) {
    int mask = b64_decode_block(m->buff, buff);
    if (mask == 0) {
      int mask = 0;
      switch (m->bufflen) {
        case 0: return 1;
        case 3: decode_one(m->buff[2], 4, &mask);
        case 2: decode_one(m->buff[1], 2, &mask);
        case 1: decode_one(m->buff[0], 1, &mask);
      }
      return mask == (4|2|1); /* must invalid character, follow Python's */
    }
    if ((mask & (8|4)) != 0) return 1; /* follow Python's */
    if (!w(ud, buff, 1)) return 0;
    if (m->buff[3] == '=' && (mask & 2) == 0) {
      if (!w(ud, &buff[1], 1)) return 0;
      mask = 0;
    }
    return m->buff[2] == '=' || mask == 0;
  }
  else {
    if (m->bufflen != 0) {
      char srcbuff[B64_ENCSIZE] = {0};
      switch (m->bufflen) {
        case 2: srcbuff[1] = m->buff[1];
        case 1: srcbuff[0] = m->buff[0];
      }
      b64_encode_block(srcbuff, m->buff);
      switch (m->bufflen) {
        case 1: buff[2] = '=';
        case 2: buff[3] = '=';
      }
      if (!w(ud, buff, B64_ENCSIZE)) return 0;
    }
  }
  return 1;
}

int b64(int is_decode, const char *s, size_t len, b64_Writer w, void *ud) {
  b64_t m;
  b64_init(&m, is_decode);
  return b64_update(&m, s, len, w, ud)
      && b64_finish(&m, w, ud);
}
