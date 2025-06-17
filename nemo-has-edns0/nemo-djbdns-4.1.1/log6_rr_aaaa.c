#include "dns.h"
#include "log.h"

void log6_rr_aaaa(const ip6_address *server, const dns_domain *name, const ip6_address *a, uint32_t ttl)
{
  log6_ip_ttl_type_name("rr", server, ttl, dns_t_aaaa, name);
  log_space();
  log_ip6(a);
  log_line();
}
