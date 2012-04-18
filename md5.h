#ifndef md5_h
#define md5_h


#include <stddef.h>

#define MD5_HASHSIZE  16
#define MD5_BLOCKSIZE 64


typedef unsigned int md5_uint32_t;
typedef unsigned long md5_size_t;
typedef char md5_static_assert_uint_is_32[
    sizeof(md5_uint32_t) >= 4 ? 1 : -1];
typedef char md5_static_assert_ulong_is_32[
    sizeof(md5_size_t) >= 4 ? 1 : -1];

typedef struct md5_t {
  md5_uint32_t d[MD5_HASHSIZE/4];
  char buff[MD5_BLOCKSIZE];
  md5_size_t len;
  size_t bufflen;
} md5_t;


void md5_init   (md5_t *m);
void md5_update (md5_t *m, const char *message, size_t len);
void md5_finish (md5_t *m, char output[MD5_HASHSIZE]);
void md5 (const char *message, size_t len, char output[MD5_HASHSIZE]);


#endif /* md5_h */
