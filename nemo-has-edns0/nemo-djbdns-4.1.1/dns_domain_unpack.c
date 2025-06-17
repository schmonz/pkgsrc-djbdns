#include "dns.h"

unsigned int dns_domain_unpack(dns_domain *out, const void *data)
{
  return dns_domain_copyb(out, data, byte_domain_length(data));
}
