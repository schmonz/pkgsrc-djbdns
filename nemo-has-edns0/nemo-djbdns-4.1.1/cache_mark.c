#include <nemo/byte.h>

#include "cache.h"

/* #define DEBUG 1 */
/* #include "debug.h" */

void cache_mark(const dns_type *type, const dns_domain *name, unsigned int status, uint32_t ttl)
{
  static byte_t empty[] = "\0";

  unsigned int keylen;
  byte_t key[257];

  keylen = cache_make_key(type, name, key);
  cache_set(key, keylen, status, empty, 0, ttl);
}
