#include "dnscache.h"
#include "dd.h"

unsigned int global_ip6(const dns_domain *name, ip6_address *ip)
{
  if (dns_domain_equal(name, dns_d_ip6_localhost)) {
    ip6_copy(ip, localhost_ip6);
    return 1;
  }
  if (dns_domain_equal(name, dns_d_ip6_localnet)) {
    ip6_copy(ip, localnet_ip6);
    return 1;
  }
  if (dns_domain_equal(name, dns_d_ip6_mcastprefix)) {
    ip6_copy(ip, mcastprefix_ip6);
    return 1;
  }
  if (dns_domain_equal(name, dns_d_ip6_allnodes)) {
    ip6_copy(ip, allnodes_ip6);
    return 1;
  }
  if (dns_domain_equal(name, dns_d_ip6_allrouters)) {
    ip6_copy(ip, allrouters_ip6);
    return 1;
  }
  if (dns_domain_equal(name, dns_d_ip6_allhosts)) {
    ip6_copy(ip, allhosts_ip6);
    return 1;
  }
/*
  if (dd6(name, dns_d_empty, ip) == 32) return 1;
*/
  return 0;
}
