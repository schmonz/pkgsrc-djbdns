#include <nemo/byte.h>

#include "cache.h"
#include "safe.h"

#define MAX_KEY_LEN 257

cache_t cache_get_rr_cname(const dns_domain *name, dns_domain *cname)
{
  byte_t *cached;
  unsigned int cached_len;
  unsigned int keylen;
  byte_t key[MAX_KEY_LEN];
  cache_t status;
  uint32_t ttl;

  keylen = cache_make_key(dns_t_cname, name, key);
  status = cache_get(key, keylen, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    if (!safe_packet_getname(cached, cached_len, 0, cname)) return CACHE_NXDOMAIN;
  }
  return status;
}
