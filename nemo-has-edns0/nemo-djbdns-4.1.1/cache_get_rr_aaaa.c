#include <nemo/byte.h>

#include "cache.h"
#include "die.h"

#define MAX_KEY_LEN 257

/* allow for empty results */
cache_t cache_get_rr_aaaa(const dns_domain *name, ip6_vector *v)
{
  byte_t *cached;
  unsigned int cached_len;
  unsigned int keylen;
  byte_t key[MAX_KEY_LEN];
  ip6_address ip6;
  uint32_t ttl;
  cache_t status;

  keylen = cache_make_key(dns_t_aaaa, name, key);
  status = cache_get(key, keylen, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    if (!ip6_vector_erase(v)) die_nomem();
    while (cached_len >= 16) {
      ip6_unpack(&ip6, cached);
      if (!ip6_vector_append(v, &ip6)) die_nomem();
      cached += 16;
      cached_len -= 16;
    }
    if (!v->len) return CACHE_NXDOMAIN;
  }
  return status;
}
