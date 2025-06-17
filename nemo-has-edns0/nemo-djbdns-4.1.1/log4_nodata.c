#include "dns.h"
#include "log.h"

void log4_nodata(const ip4_address *server, const dns_domain *name, const dns_type *type, uint32_t ttl)
{
  log4_ip_ttl_type_name("nodata", server, ttl, type, name);
  log_line();
}
