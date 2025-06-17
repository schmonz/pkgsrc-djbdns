#include <nemo/byte.h>

#include "cache.h"

#define MAX_KEY_LEN 257

cache_t cache_test_rr(const dns_type *type, const dns_domain *name)
{
  byte_t *cached;
  unsigned int cached_len;
  unsigned int keylen;
  byte_t key[257];
  uint32_t ttl;

  keylen = cache_make_key(type, name, key);
  return cache_get(key, keylen, &cached, &cached_len, &ttl);
}
