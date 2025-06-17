#include "dns.h"

unsigned int dns_domain_copy(dns_domain *out, const dns_domain *in)
{
  return dns_domain_copyb(out, in->data, in->len);
}
