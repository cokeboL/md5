#ifndef hash_api_h
#define hash_api_h


#define hash_t hash_t_(hash)
#define hash_t_(x) hash_t_r_(x)
#define hash_t_r_(x) x##_t

#define HASH_HASHSIZE HASH_HASHSIZE_(HASH)
#define HASH_HASHSIZE_(x) HASH_HASHSIZE_R_(x)
#define HASH_HASHSIZE_R_(x) x##_HASHSIZE

#define HASH_BLOCKSIZE HASH_BLOCKSIZE_(HASH)
#define HASH_BLOCKSIZE_(x) HASH_BLOCKSIZE_R_(x)
#define HASH_BLOCKSIZE_R_(x) x##_BLOCKSIZE

#define hash_init hash_init_(hash)
#define hash_init_(x) hash_init_r_(x)
#define hash_init_r_(x) x##_init

#define hash_update hash_update_(hash)
#define hash_update_(x) hash_update_r_(x)
#define hash_update_r_(x) x##_update

#define hash_finish hash_finish_(hash)
#define hash_finish_(x) hash_finish_r_(x)
#define hash_finish_r_(x) x##_finish


void hash_init(hash_t *m) {
  init_digest(m->d);
  m->len = m->bufflen = 0;
}
void hash_update(hash_t *m,
        const char *message, size_t len) {
  WORD32 wbuff[MLEN];
  if (m->bufflen != 0) {
    int numbytes = m->bufflen+len < HASH_BLOCKSIZE ? len :
      HASH_BLOCKSIZE - m->bufflen;
    memcpy(&m->buff[m->bufflen], message, numbytes);
    if ((m->bufflen += numbytes) < HASH_BLOCKSIZE)
      return;
    bytestoword32(wbuff, m->buff);
    digest(wbuff, m->d);
    m->len += HASH_BLOCKSIZE;
    message += numbytes;
    len -= numbytes;
  }
  while (len >= HASH_BLOCKSIZE) {
    bytestoword32(wbuff, message);
    digest(wbuff, m->d);
    m->len += HASH_BLOCKSIZE;
    message += HASH_BLOCKSIZE;
    len -= HASH_BLOCKSIZE;
  }
  memcpy(m->buff, message, len);
  m->bufflen = len;
}
void hash_finish(hash_t *m, char output[HASH_HASHSIZE]) {
  WORD32 wbuff[MLEN];
  m->len += m->bufflen;
  m->buff[m->bufflen++] = '\x80';
  memset(&m->buff[m->bufflen], 0, HASH_BLOCKSIZE-m->bufflen);
  bytestoword32(wbuff, m->buff);
  if (m->bufflen > (HASH_BLOCKSIZE-8)) {
    digest(wbuff, m->d);
    memset(wbuff, 0, HASH_BLOCKSIZE);
  }
  wbuff[HASH_BLOCKSIZE/4-2] = (m->len>>(WSIZE-3)) & 0x7;
  wbuff[HASH_BLOCKSIZE/4-1] = (m->len<<3) & MASK;
  digest(wbuff, m->d);
  word32tobytes(m->d, output);
}
void hash(const char *message, size_t len,
        char output[HASH_HASHSIZE]) {
  hash_t m;
  hash_init(&m);
  hash_update(&m, message, len);
  hash_finish(&m, output);
}


#undef hash_t
#undef hash_t_
#undef hash_t_r_

#undef HASH_HASHSIZE
#undef HASH_HASHSIZE_
#undef HASH_HASHSIZE_R_

#undef HASH_BLOCKSIZE
#undef HASH_BLOCKSIZE_
#undef HASH_BLOCKSIZE_R_

#undef hash_init
#undef hash_init_
#undef hash_init_r_

#undef hash_update
#undef hash_update_
#undef hash_update_r_

#undef hash_finish
#undef hash_finish_
#undef hash_finish_r_

#undef hash
#undef HASH

#endif /* hash_api_h */
