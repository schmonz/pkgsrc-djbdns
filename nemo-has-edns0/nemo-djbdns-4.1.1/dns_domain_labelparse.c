#include "dns.h"

unsigned int dns_domain_labelparse(const dns_domain *dn, sa_vector *out)
{
  register byte_t *d;

  if (!dn->data) return 0;
  if (!sa_vector_erase(out)) return 0;
  d = dn->data;
  while (*d) {
    if (!sa_vector_appendb(out, d + 1, *d)) return 0;
    d += *d + 1;
  }
  sa_vector_reverse(out);
  return 1;
}
