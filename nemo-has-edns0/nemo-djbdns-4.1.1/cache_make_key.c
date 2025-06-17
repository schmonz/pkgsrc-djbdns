#include <nemo/byte.h>

#include "cache.h"
#include "die.h"

unsigned int cache_make_key(const dns_type *type, const dns_domain *name, byte_t *key)
{
  register unsigned int len;

  len = dns_domain_length(name);
  if (len > 255) die_bogus_query("invalid name length");
  dns_type_pack(type, key);
  dns_domain_pack(name, key + 2);
  byte_lower(key + 2, len);
  return len + 2;
}
