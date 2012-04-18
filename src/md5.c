#include "md5.h"


#include <string.h>


#define WORD 32
#define MASK 0xFFFFFFFF

/*
** Realiza a rotacao no sentido horario dos bits da variavel 'D' do tipo WORD32.
** Os bits sao deslocados de 'num' posicoes
*/
#define rotate(D, num)  ((D<<num) | (D>>(WORD-num)))

/*Macros que definem operacoes relizadas pelo algoritmo  md5 */
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))


/*vetor de numeros utilizados pelo algoritmo md5 para embaralhar bits */
static const WORD32 T[64]={
  0XD76AA478, 0XE8C7B756, 0X242070DB, 0XC1BDCEEE,
  0XF57C0FAF, 0X4787C62A, 0XA8304613, 0XFD469501,
  0X698098D8, 0X8B44F7AF, 0XFFFF5BB1, 0X895CD7BE,
  0X6B901122, 0XFD987193, 0XA679438E, 0X49B40821,
  0XF61E2562, 0XC040B340, 0X265E5A51, 0XE9B6C7AA,
  0XD62F105D, 0X02441453, 0XD8A1E681, 0XE7D3FBC8,
  0X21E1CDE6, 0XC33707D6, 0XF4D50D87, 0X455A14ED,
  0XA9E3E905, 0XFCEFA3F8, 0X676F02D9, 0X8D2A4C8A,
  0XFFFA3942, 0X8771F681, 0X6D9D6122, 0XFDE5380C,
  0XA4BEEA44, 0X4BDECFA9, 0XF6BB4B60, 0XBEBFBC70,
  0X289B7EC6, 0XEAA127FA, 0XD4EF3085, 0X04881D05,
  0XD9D4D039, 0XE6DB99E5, 0X1FA27CF8, 0XC4AC5665,
  0XF4292244, 0X432AFF97, 0XAB9423A7, 0XFC93A039,
  0X655B59C3, 0X8F0CCC92, 0XFFEFF47D, 0X85845DD1,
  0X6FA87E4F, 0XFE2CE6E0, 0XA3014314, 0X4E0811A1,
  0XF7537E82, 0XBD3AF235, 0X2AD7D2BB, 0XEB86D391,
};


static void init_digest(WORD32 d[4]) {
  d[0] = 0x67452301;
  d[1] = 0xEFCDAB89;
  d[2] = 0x98BADCFE;
  d[3] = 0x10325476;
}


/*funcao que implemeta os quatro passos principais do algoritmo MD5 */
static void digest(const WORD32 m[16], WORD32 d[4]) {
  int i;
  WORD32 od[4];
  od[0] = d[0]; od[1] = d[1]; od[2] = d[2]; od[3] = d[3];
  /* MD5 PASSO1 */
  for (i = 0; i < 4*4; i += 4) {
    d[0] += F(d[1], d[2], d[3]) + m[i+0] + T[i+0];
    d[0]  = rotate(d[0],  7) + d[1];
    d[3] += F(d[0], d[1], d[2]) + m[i+1] + T[i+1];
    d[3]  = rotate(d[3], 12) + d[0];
    d[2] += F(d[3], d[0], d[1]) + m[i+2] + T[i+2];
    d[2]  = rotate(d[2], 17) + d[3];
    d[1] += F(d[2], d[3], d[0]) + m[i+3] + T[i+3];
    d[1]  = rotate(d[1], 22) + d[2];
  }
  /* MD5 PASSO2 */
  for (i = 0; i < 4*4; i += 4) {
    d[0] += G(d[1], d[2], d[3]) + m[(5*(i+0)+1)&0x0F] + T[(i-1)+17];
    d[0]  = rotate(d[0],  5) + d[1];
    d[3] += G(d[0], d[1], d[2]) + m[(5*(i+1)+1)&0x0F] + T[(i+0)+17];
    d[3]  = rotate(d[3],  9) + d[0];
    d[2] += G(d[3], d[0], d[1]) + m[(5*(i+2)+1)&0x0F] + T[(i+1)+17];
    d[2]  = rotate(d[2], 14) + d[3];
    d[1] += G(d[2], d[3], d[0]) + m[(5*(i+3)+1)&0x0F] + T[(i+2)+17];
    d[1]  = rotate(d[1], 20) + d[2];
  }
  /* MD5 PASSO3 */
  for (i = 0; i < 4*4; i += 4) {
    d[0] += H(d[1], d[2], d[3])+ m[(3*(i+0)+5)&0x0F] + T[(i-1)+33];
    d[0]  = rotate(d[0],  4) + d[1];
    d[3] += H(d[0], d[1], d[2])+ m[(3*(i+1)+5)&0x0F] + T[(i+0)+33];
    d[3]  = rotate(d[3], 11) + d[0];
    d[2] += H(d[3], d[0], d[1])+ m[(3*(i+2)+5)&0x0F] + T[(i+1)+33];
    d[2]  = rotate(d[2], 16) + d[3];
    d[1] += H(d[2], d[3], d[0])+ m[(3*(i+3)+5)&0x0F] + T[(i+2)+33];
    d[1]  = rotate(d[1], 23) + d[2];
  }
  /* MD5 PASSO4 */
  for (i = 0; i < 4*4; i += 4) {
    d[0] += I(d[1], d[2], d[3])+ m[(7*(i+0))&0x0F] + T[(i-1)+49];
    d[0]  = rotate(d[0], 6) + d[1];
    d[3] += I(d[0], d[1], d[2])+ m[(7*(i+1))&0x0F] + T[(i+0)+49];
    d[3]  = rotate(d[3], 10) + d[0];
    d[2] += I(d[3], d[0], d[1])+ m[(7*(i+2))&0x0F] + T[(i+1)+49];
    d[2]  = rotate(d[2], 15) + d[3];
    d[1] += I(d[2], d[3], d[0])+ m[(7*(i+3))&0x0F] + T[(i+2)+49];
    d[1]  = rotate(d[1], 21) + d[2];
  }
  d[0] += od[0]; d[1] += od[1]; d[2] += od[2]; d[3] += od[3];
}


static void word32tobytes (const WORD32 input[4], char output[16]) {
  int i;
  for (i = 0; i < 4; ++i) {
    WORD32 v = input[i];
    *output++ = v & 0xFF; v >>= 8;
    *output++ = v & 0xFF; v >>= 8;
    *output++ = v & 0xFF; v >>= 8;
    *output++ = v & 0xFF;
  }
}


static void bytestoword32 (WORD32 output[16], const char input[64]) {
  int i, j;
  for (i = j = 0; i < 16; ++i, j += 4) {
    output[i] = (((input[j+3] & 0xFF)  << 8 |
                  (input[j+2] & 0xFF)) << 8 |
                  (input[j+1] & 0xFF)) << 8 |
                  (input[j+0] & 0xFF);
  }
}


void md5_init(md5_t *m) {
  init_digest(m->d);
  m->len = m->bufflen = 0;
}


void md5_update(md5_t *m, const char *message, size_t len) {
  WORD32 wbuff[16];
  if (m->bufflen != 0) {
    int numbytes = m->bufflen+len < 64 ? len : 64 - m->bufflen;
    memcpy(m->buff, message, numbytes);
    if ((m->bufflen += numbytes) < 64)
      return;
    bytestoword32(wbuff, m->buff);
    digest(wbuff, m->d);
    m->len += 64;
    message += numbytes;
    len -= numbytes;
  }
  while (len >= 64) {
    bytestoword32(wbuff, message);
    digest(wbuff, m->d);
    m->len += 64;
    message += 64;
    len -= 64;
  }
  memcpy(m->buff, message, len);
  m->bufflen = len;
}


void md5_finish(md5_t *m, char output[16]) {
  WORD32 wbuff[16];
  m->len += m->bufflen;
  m->buff[m->bufflen++] = '\x80';
  memset(&m->buff[m->bufflen], 0, 64-m->bufflen);
  bytestoword32(wbuff, m->buff);
  if (m->bufflen > (64-8)) {
    digest(wbuff, m->d);
    memset(wbuff, 0, 64);
  }
  wbuff[14] = (m->len<<    3 ) & MASK;
  wbuff[15] = (m->len>>(32-3)) &  0x7;
  digest(wbuff, m->d);
  word32tobytes(m->d, output);
}


void md5(const char *message, size_t len, char output[16]) {
  md5_t m;
  md5_init(&m);
  md5_update(&m, message, len);
  md5_finish(&m, output);
}
