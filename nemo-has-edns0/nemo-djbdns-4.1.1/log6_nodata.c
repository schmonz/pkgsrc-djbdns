#include "dns.h"
#include "log.h"

void log6_nodata(const ip6_address *server, const dns_domain *name, const dns_type *type, uint32_t ttl)
{
  log6_ip_ttl_type_name("nodata", server, ttl, type, name);
  log_line();
}
