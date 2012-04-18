#include "sha1.h"


#include <string.h>
/*#define SHA1_REID [> uncomment it to enable REID <]*/


#define WORD32 sha1_uint32_t
#define WSIZE 32
#define MASK 0xFFFFFFFF
#define DLEN (SHA1_HASHSIZE/4)
#ifdef SHA1_REID
#  define MLEN (SHA1_BLOCKSIZE/4)
#else
#  define MLEN (SHA1_BLOCKSIZE/4*5)
#endif

/*
** Realiza a rotacao no sentido horario dos bits da variavel 'D' do tipo WORD32.
** Os bits sao deslocados de 'num' posicoes
*/
#define ROL(D, num)  (((D)<<(num)) | ((D)>>(WSIZE-(num))))


static void init_digest(WORD32 d[DLEN]) {
  d[0] = 0x67452301;
  d[1] = 0xEFCDAB89;
  d[2] = 0x98BADCFE;
  d[3] = 0x10325476;
  d[4] = 0xC3D2E1F0;
}


/*funcao que implemeta os quatro passos principais do algoritmo MD5 */
static void digest(WORD32 M[MLEN], WORD32 D[DLEN]) {
  register unsigned int a=D[0], b=D[1], c=D[2], d=D[3], e=D[4];
#ifdef SHA1_REID	/* 7K on an intel */
  /*
   * blk() perform the initial expand.
   * I got the idea of expanding during the round function from SSLeay
   */
#define blk(i) (M[i&15] = ROL(M[(i+13)&15]^M[(i+8)&15]^M[(i+2)&15]^M[i&15],1))
  /*
   * (R0+R1), R2, R3, R4 are the different operations used in SHA1
   */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+(i)+0x5A827999+ROL(v,5);w=ROL(w,30)
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+ROL(v,5);w=ROL(w,30)
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+ROL(v,5);w=ROL(w,30)
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+ROL(v,5);w=ROL(w,30)
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+ROL(v,5);w=ROL(w,30)

  /*
   * 4 rounds of 20 operations each. Loop unrolled.
   */

  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

#else /* not SHA1_REID: plain from RFC ~2.8K on intel, +25% slower */
  WORD32 tmp, *u, *end;
  for (u = M+15, end = M+80; ++u < end;)
    *u = ROL(u[-3]^u[-8]^u[-14]^u[-16], 1);
  for (u = M-1, end = M+20; ++u < end;) {
    tmp = ROL(a, 5) + ((b&c) | (~b&d)) + e + *u + 0x5A827999;
    e=d; d=c; c=ROL(b,30); b=a; a=tmp;
  }
  for (u = M+19, end = M+40; ++u < end;) {
    tmp = ROL(a, 5) + (b^c^d) + e + *u + 0x6ED9EBA1;
    e=d; d=c; c=ROL(b, 30); b=a; a=tmp;
  }
  for (u = M+39, end = M+60; ++u < end;) {
    tmp = ROL(a, 5) + ((b&(c|d))|(c&d)) + e + *u + 0x8F1BBCDC;
    e=d; d=c; c=ROL(b, 30); b=a; a=tmp;
  }
  for (u = M+59, end = M+80; ++u < end;) {
    tmp = ROL(a, 5) + (b^c^d) + e + *u + 0xCA62C1D6;
    e=d; d=c; c=ROL(b, 30); b=a; a=tmp;
  }
#endif /* SHA1_REID */
  /*
   * Add the working vars back into context.state[]
   */
  D[0] += a; D[1] += b; D[2] += c; D[3] += d; D[4] += e;
}


static void word32tobytes (const WORD32 input[DLEN], char output[SHA1_HASHSIZE]) {
  int i;
  for (i = 0; i < DLEN; ++i) {
    *output++ = (input[i] >> 24) & 0xFF;
    *output++ = (input[i] >> 16) & 0xFF;
    *output++ = (input[i] >>  8) & 0xFF;
    *output++ = (input[i] >>  0) & 0xFF;
  }
}


static void bytestoword32 (WORD32 output[MLEN], const char input[SHA1_BLOCKSIZE]) {
  int i;
  for (i = 0; i < SHA1_BLOCKSIZE/4; ++i) {
    WORD32 v = 0;
    v |= *input++ & 0xFF; v <<= 8;
    v |= *input++ & 0xFF; v <<= 8;
    v |= *input++ & 0xFF; v <<= 8;
    v |= *input++ & 0xFF;
    *output++ = v;
  }
}


void sha1_init(sha1_t *m) {
  init_digest(m->d);
  m->len = m->bufflen = 0;
}


void sha1_update(sha1_t *m, const char *message, size_t len) {
  WORD32 wbuff[MLEN];
  if (m->bufflen != 0) {
    int numbytes = m->bufflen+len < SHA1_BLOCKSIZE ? len :
      SHA1_BLOCKSIZE - m->bufflen;
    memcpy(&m->buff[m->bufflen], message, numbytes);
    if ((m->bufflen += numbytes) < SHA1_BLOCKSIZE)
      return;
    bytestoword32(wbuff, m->buff);
    digest(wbuff, m->d);
    m->len += SHA1_BLOCKSIZE;
    message += numbytes;
    m->bufflen = 0;
  }
  while (len >= SHA1_BLOCKSIZE) {
    bytestoword32(wbuff, message);
    digest(wbuff, m->d);
    m->len += SHA1_BLOCKSIZE;
    message += SHA1_BLOCKSIZE;
    len -= SHA1_BLOCKSIZE;
  }
  memcpy(m->buff, message, len);
  m->bufflen = len;
}


void sha1_finish(sha1_t *m, char output[SHA1_HASHSIZE]) {
  WORD32 wbuff[MLEN];
  m->len += m->bufflen;
  m->buff[m->bufflen++] = '\x80';
  memset(&m->buff[m->bufflen], 0, SHA1_BLOCKSIZE-m->bufflen);
  bytestoword32(wbuff, m->buff);
  if (m->bufflen > (SHA1_BLOCKSIZE-8)) {
    digest(wbuff, m->d);
    memset(wbuff, 0, SHA1_BLOCKSIZE);
  }
  wbuff[SHA1_BLOCKSIZE/4-2] = (m->len>>(WSIZE-3)) & 0x7;
  wbuff[SHA1_BLOCKSIZE/4-1] = (m->len<<3) & MASK;
  digest(wbuff, m->d);
  word32tobytes(m->d, output);
}


void sha1(const char *message, size_t len, char output[SHA1_HASHSIZE]) {
  sha1_t m;
  sha1_init(&m);
  while (len >= SHA1_BLOCKSIZE) {
    sha1_update(&m, message, SHA1_BLOCKSIZE);
    message += SHA1_BLOCKSIZE;
    len -= SHA1_BLOCKSIZE;
  }
  sha1_update(&m, message, len);
  sha1_finish(&m, output);
}
