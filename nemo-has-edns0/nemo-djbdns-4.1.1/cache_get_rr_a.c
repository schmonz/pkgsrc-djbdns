#include <nemo/byte.h>

#include "cache.h"
#include "die.h"

#define MAX_KEY_LEN 257

/* allow for empty results */
cache_t cache_get_rr_a(const dns_domain *name, ip4_vector *v)
{
  ip4_address ip4;
  byte_t *cached;
  unsigned int cached_len;
  unsigned int keylen;
  byte_t key[MAX_KEY_LEN];
  uint32_t ttl;
  cache_t status;

  keylen = cache_make_key(dns_t_a, name, key);
  status = cache_get(key, keylen, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    if (!ip4_vector_erase(v)) die_nomem();
    while (cached_len >= 4) {
      ip4_unpack(&ip4, cached);
      if (!ip4_vector_append(v, &ip4)) die_nomem();
      cached += 4;
      cached_len -= 4;
    }
    if (!v->len) return CACHE_NXDOMAIN;
  }
  return status;
}
