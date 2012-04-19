#ifndef base64_h
#define base64_h


#include <stddef.h>


#define B64_ENCSIZE 3
#define B64_DECSIZE 4

typedef struct base64_t {
    char buff[4];
    size_t bufflen;
    int is_decode, mask;
} base64_t;
typedef int (*b64_Writer)(void *ud, const char *ch, size_t len);


void b64_init   (base64_t *m, int is_decode);
int  b64_update (base64_t *m, const char *s, size_t len, b64_Writer w, void *ud);
int  b64_finish (base64_t *m, b64_Writer w, void *ud);


#endif /* base64_h */
