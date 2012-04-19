#include "md5.h"


#include <string.h>


#define WORD32 md5_uint32_t
#define WSIZE 32
#define MASK 0xFFFFFFFF
#define DLEN (MD5_HASHSIZE/4)
#define MLEN (MD5_BLOCKSIZE/4)

/*
 ** Realiza a rotacao no sentido horario dos bits da variavel 'D' do tipo WORD32.
 ** Os bits sao deslocados de 'num' posicoes
 */
#define ROL(D, num)  ((D)<<(num) | (D)>>(WSIZE-(num)))

/*Macros que definem operacoes relizadas pelo algoritmo  md5 */
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))


/*vetor de numeros utilizados pelo algoritmo md5 para embaralhar bits */
static const WORD32 T[64]={
  0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
  0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
  0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
  0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
  0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
  0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
  0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
  0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
  0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
  0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
  0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
  0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
  0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
  0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
  0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
  0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
};


static void init_digest(WORD32 d[DLEN]) {
  d[0] = 0x67452301;
  d[1] = 0xEFCDAB89;
  d[2] = 0x98BADCFE;
  d[3] = 0x10325476;
}


/*funcao que implemeta os quatro passos principais do algoritmo MD5 */
static void digest(const WORD32 M[MLEN], WORD32 D[DLEN]) {
  int i;
  WORD32 a = D[0], b = D[1], c = D[2], d = D[3];
  /* MD5 PASSO1 */
  for (i = 0; i < 4*4; i += 4) {
    a += F(b, c, d) + M[i+0] + T[i+0];
    a  = ROL(a,  7) + b;
    d += F(a, b, c) + M[i+1] + T[i+1];
    d  = ROL(d, 12) + a;
    c += F(d, a, b) + M[i+2] + T[i+2];
    c  = ROL(c, 17) + d;
    b += F(c, d, a) + M[i+3] + T[i+3];
    b  = ROL(b, 22) + c;
  }
  /* MD5 PASSO2 */
  for (i = 0; i < 4*4; i += 4) {
    a += G(b, c, d) + M[(5*(i+0)+1)&0x0F] + T[(i-1)+17];
    a  = ROL(a,  5) + b;
    d += G(a, b, c) + M[(5*(i+1)+1)&0x0F] + T[(i+0)+17];
    d  = ROL(d,  9) + a;
    c += G(d, a, b) + M[(5*(i+2)+1)&0x0F] + T[(i+1)+17];
    c  = ROL(c, 14) + d;
    b += G(c, d, a) + M[(5*(i+3)+1)&0x0F] + T[(i+2)+17];
    b  = ROL(b, 20) + c;
  }
  /* MD5 PASSO3 */
  for (i = 0; i < 4*4; i += 4) {
    a += H(b, c, d) + M[(3*(i+0)+5)&0x0F] + T[(i-1)+33];
    a  = ROL(a,  4) + b;
    d += H(a, b, c) + M[(3*(i+1)+5)&0x0F] + T[(i+0)+33];
    d  = ROL(d, 11) + a;
    c += H(d, a, b) + M[(3*(i+2)+5)&0x0F] + T[(i+1)+33];
    c  = ROL(c, 16) + d;
    b += H(c, d, a) + M[(3*(i+3)+5)&0x0F] + T[(i+2)+33];
    b  = ROL(b, 23) + c;
  }
  /* MD5 PASSO4 */
  for (i = 0; i < 4*4; i += 4) {
    a += I(b, c, d) + M[(7*(i+0)+0)&0x0F] + T[(i-1)+49];
    a  = ROL(a,  6) + b;
    d += I(a, b, c) + M[(7*(i+1)+0)&0x0F] + T[(i+0)+49];
    d  = ROL(d, 10) + a;
    c += I(d, a, b) + M[(7*(i+2)+0)&0x0F] + T[(i+1)+49];
    c  = ROL(c, 15) + d;
    b += I(c, d, a) + M[(7*(i+3)+0)&0x0F] + T[(i+2)+49];
    b  = ROL(b, 21) + c;
  }
  D[0] += a; D[1] += b; D[2] += c; D[3] += d;
}


static void word32tobytes (const WORD32 input[DLEN], char output[MD5_HASHSIZE]) {
  int i;
  for (i = 0; i < DLEN; ++i) {
    WORD32 v = input[i];
    *output++ = v & 0xFF; v >>= 8;
    *output++ = v & 0xFF; v >>= 8;
    *output++ = v & 0xFF; v >>= 8;
    *output++ = v & 0xFF;
  }
}


static void bytestoword32 (WORD32 output[MLEN], const char input[MD5_BLOCKSIZE]) {
  int i, j;
  for (i = j = 0; i < MLEN; ++i, j += 4) {
    output[i] = (((input[j+3] & 0xFF)  << 8 |
                  (input[j+2] & 0xFF)) << 8 |
                  (input[j+1] & 0xFF)) << 8 |
                  (input[j+0] & 0xFF);
  }
}


#define hash md5
#define HASH MD5
#define DEFINE_IMPL
#include "hash_impl.h"
