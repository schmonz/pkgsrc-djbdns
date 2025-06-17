#include "dns.h"

unsigned int dns_domain_active(const dns_domain *dn)
{
  return (!!(dn->data));
}
