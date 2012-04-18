#ifndef sha1_h
#define sha1_h


#include <stddef.h>

#define SHA1_HASHSIZE  20
#define SHA1_BLOCKSIZE 64


typedef unsigned int sha1_uint32_t;
typedef unsigned long sha1_size_t;
typedef char sha1_static_assert_uint_is_32[
    sizeof(sha1_uint32_t) >= 4 ? 1 : -1];
typedef char sha1_static_assert_ulong_is_32[
    sizeof(sha1_size_t) >= 4 ? 1 : -1];

typedef struct sha1_t {
  sha1_uint32_t d[SHA1_HASHSIZE/4];
  char buff[SHA1_BLOCKSIZE];
  sha1_size_t len;
  size_t bufflen;
} sha1_t;


void sha1_init   (sha1_t *m);
void sha1_update (sha1_t *m, const char *message, size_t len);
void sha1_finish (sha1_t *m, char output[SHA1_HASHSIZE]);
void sha1 (const char *message, size_t len, char output[SHA1_HASHSIZE]);


#endif /* sha1_h */
