#include "dns.h"
#include "log.h"

void log6_rr_a(const ip6_address *server, const dns_domain *name, const ip4_address *a, uint32_t ttl)
{
  log6_ip_ttl_type_name("rr", server, ttl, dns_t_a, name);
  log_space();
  log_ip4(a);
  log_line();
}
