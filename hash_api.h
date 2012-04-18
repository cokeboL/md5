#ifndef hash_api_h
#define hash_api_h


#define DEFINE_HASH_API(hash, HASH) \
void hash##_init(hash##_t *m) { \
  init_digest(m->d); \
  m->len = m->bufflen = 0; \
} \
void hash##_update(hash##_t *m, \
        const char *message, size_t len) { \
  WORD32 wbuff[MLEN]; \
  if (m->bufflen != 0) { \
    int numbytes = m->bufflen+len < HASH##_BLOCKSIZE ? len : \
      HASH##_BLOCKSIZE - m->bufflen; \
    memcpy(&m->buff[m->bufflen], message, numbytes); \
    if ((m->bufflen += numbytes) < HASH##_BLOCKSIZE) \
      return; \
    bytestoword32(wbuff, m->buff); \
    digest(wbuff, m->d); \
    m->len += HASH##_BLOCKSIZE; \
    message += numbytes; \
    len -= numbytes; \
  } \
  while (len >= HASH##_BLOCKSIZE) { \
    bytestoword32(wbuff, message); \
    digest(wbuff, m->d); \
    m->len += HASH##_BLOCKSIZE; \
    message += HASH##_BLOCKSIZE; \
    len -= HASH##_BLOCKSIZE; \
  } \
  memcpy(m->buff, message, len); \
  m->bufflen = len; \
} \
void hash##_finish(hash##_t *m, char output[HASH##_HASHSIZE]) { \
  WORD32 wbuff[MLEN]; \
  m->len += m->bufflen; \
  m->buff[m->bufflen++] = '\x80'; \
  memset(&m->buff[m->bufflen], 0, HASH##_BLOCKSIZE-m->bufflen); \
  bytestoword32(wbuff, m->buff); \
  if (m->bufflen > (HASH##_BLOCKSIZE-8)) { \
    digest(wbuff, m->d); \
    memset(wbuff, 0, HASH##_BLOCKSIZE); \
  } \
  wbuff[HASH##_BLOCKSIZE/4-2] = (m->len>>(WSIZE-3)) & 0x7; \
  wbuff[HASH##_BLOCKSIZE/4-1] = (m->len<<3) & MASK; \
  digest(wbuff, m->d); \
  word32tobytes(m->d, output); \
} \
void hash(const char *message, size_t len, \
        char output[HASH##_HASHSIZE]) { \
  hash##_t m; \
  hash##_init(&m); \
  hash##_update(&m, message, len); \
  hash##_finish(&m, output); \
}


#endif /* hash_api_h */
