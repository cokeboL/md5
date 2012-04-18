#include "base64.h"

#include <string.h>


void b64_init(base64_t *m, int is_decode) {
    m->bufflen = 0;
    m->is_decode = 0;
}

int b64_update(base64_t *m, const char *s, size_t len, b64_Writer w, void *ud) {
    return 0;
}

int b64_finish(base64_t *m, b64_Writer w, void *ud) {
    return 0;
}

int base64(int is_decode, const char *s, size_t len, b64_Writer w, void *ud) {
    base64_t m;
    b64_init(&m, is_decode);
    if (!b64_update(&m, s, len, w, ud))
        return 0;
    b64_finish(&m, w, ud);
    return 1;
}
