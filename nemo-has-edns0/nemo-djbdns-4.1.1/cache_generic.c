#include "cache.h"

/* #define DEBUG 1 */
/* #include "debug.h" */

void cache_generic(const dns_type *type, const dns_domain *name, const byte_t *data, unsigned int data_len, uint32_t ttl)
{
  unsigned int keylen;
  byte_t key[257];

  keylen = cache_make_key(type, name, key);
  cache_set(key, keylen, CACHE_HIT, data, data_len, ttl);
}
