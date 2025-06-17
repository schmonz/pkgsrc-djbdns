#include <nemo/byte.h>

#include "cache.h"
#include "die.h"
#include "safe.h"

#define MAX_KEY_LEN 257

cache_t cache_get_rr_ns(const dns_domain *name, dn_vector *v)
{
  static dns_domain t1 = DNS_DOMAIN;
  byte_t *cached;
  unsigned int cached_len;
  unsigned int pos;
  unsigned int keylen;
  byte_t key[MAX_KEY_LEN];
  uint32_t ttl;
  cache_t status;

  keylen = cache_make_key(dns_t_ns, name, key);
  status = cache_get(key, keylen, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    if (!dn_vector_erase(v)) die_nomem();
    pos = 0;
    for (;;) {
      pos = safe_packet_getname(cached, cached_len, pos, &t1);
      if (!pos) break;
      if (!dn_vector_append(v, &t1)) die_nomem();
    }
    if (!v->len) return CACHE_NXDOMAIN;
  }
  return status;
}
