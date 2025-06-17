#include "dns.h"

unsigned int dns_domain_cat(dns_domain *out, const dns_domain *in)
{
  return dns_domain_catb(out, in->data, in->len);
}
