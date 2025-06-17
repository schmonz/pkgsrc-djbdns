#include "dns.h"
#include "log.h"

void log6_ip_ttl_type_name(const char *prefix, const ip6_address *server, uint32_t ttl, const dns_type *type, const dns_domain *name)
{
  log_prefix(prefix);
  log_ip6(server);
  log_space();
  log_number(ttl);
  log_space();
  log_type(type);
  log_space();
  log_domain(name);
}
