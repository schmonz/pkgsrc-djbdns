#include "dns.h"

unsigned int dns_domain_labellength(const dns_domain *dn)
{
  if (!dn->data) return 0;
  return dn->data[0];
}
