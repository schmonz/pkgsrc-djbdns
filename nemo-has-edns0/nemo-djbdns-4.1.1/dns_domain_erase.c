#include "dns.h"

unsigned int dns_domain_erase(dns_domain *dn)
{
  if (!dns_domain_ready(dn, 1)) return 0;
  dn->data[0] = '\0';
  dn->len = 1;
  return 1;
}
