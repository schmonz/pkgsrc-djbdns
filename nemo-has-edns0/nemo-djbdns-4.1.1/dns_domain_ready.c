#include <nemo/alloc.h>

#include "dns.h"

#define MIN_SIZE 32

static inline unsigned int alloc_size(register unsigned int len)
{
  if (len <= MIN_SIZE) return MIN_SIZE;
  return ((len >> 4) + ((len & 15) ? 1 : 0)) << 4;  /* round up to 16 byte chunks */
}

unsigned int dns_domain_realloc(register dns_domain *dn, register unsigned int n)
{
  register unsigned int i;

  i = dn->a;
  dn->a = alloc_size(n);
  if (alloc_re((void **)&dn->data, i, dn->a)) return 1;
  dn->a = i;
  return 0;
}

unsigned int dns_domain_alloc(register dns_domain *dn, register unsigned int n)
{
  dn->len = 0;
  dn->a = alloc_size(n);
  return (!!(dn->data = (byte_t *)alloc(dn->a)));
}
