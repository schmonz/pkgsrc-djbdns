#include "dns.h"
#include "log.h"

void log6_rr_cname(const ip6_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl)
{
  log6_ip_ttl_type_name("rr", server, ttl, dns_t_cname, name);
  log_space();
  log_domain(data);
  log_line();
}
