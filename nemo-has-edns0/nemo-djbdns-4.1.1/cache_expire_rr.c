#include <nemo/byte.h>

#include "cache.h"

/* #define DEBUG 1 */
/* #include "debug.h" */

#define MAX_KEY_LEN 257

void cache_expire_rr(const dns_type *type, const dns_domain *name)
{
  unsigned int keylen;
  byte_t key[MAX_KEY_LEN];

  keylen = cache_make_key(type, name, key);
  cache_expire(key, keylen);
}
