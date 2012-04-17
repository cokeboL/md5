#ifndef md5_h
#define md5_h


#include <stddef.h>


typedef unsigned int WORD32;
typedef unsigned long md5_size_t;

typedef struct md5_t {
  WORD32 d[4];
  char buff[64];
  md5_size_t len;
  size_t bufflen;
} md5_t;


void md5_init   (md5_t *m);
void md5_update (md5_t *m, const char *message, size_t len);
void md5_finish (md5_t *m, char output[16]);
void md5 (const char *message, size_t len, char output[16]);


#endif /* md5_h */
