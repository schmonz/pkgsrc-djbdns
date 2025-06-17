#include "dns.h"

unsigned int dns_domain_labelcount(const dns_domain *dn)
{
  register unsigned int count;
  register byte_t *d;

  if (!dn->data) return 0;
  d = dn->data;
  count = 0;
  while (*d) {
    count++;
    d += *d + 1;
  }
  return count;
}
