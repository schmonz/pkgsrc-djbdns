#include "dnscache.h"
#include "dd.h"

unsigned int global_ip4(const dns_domain *name, ip4_address *ip)
{
  if (dns_domain_equal(name, dns_d_ip4_localhost)) {
    ip4_copy(ip, localhost_ip4);
    return 1;
  }
  if (dd4(name, dns_d_empty, ip) == 4) return 1;
  return 0;
}
