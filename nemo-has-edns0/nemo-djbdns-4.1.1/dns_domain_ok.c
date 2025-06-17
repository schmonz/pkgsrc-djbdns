#include "dns.h"

unsigned int dns_domain_ok(const dns_domain *dn)
{
  if (!dn->data) return 1;
  return dn->len == byte_domain_length(dn->data);
}
