#include "dns.h"
#include "log.h"

void log4_rr_ptr(const ip4_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl)
{
  log4_ip_ttl_type_name("rr", server, ttl, dns_t_ptr, name);
  log_space();
  log_domain(data);
  log_line();
}
