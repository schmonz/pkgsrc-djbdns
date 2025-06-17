#include "dns.h"
#include "log.h"

void log6_rr(const ip6_address *server, const dns_domain *name, const dns_type *type, const byte_t *buf, unsigned int len, uint32_t ttl)
{
  unsigned int i;

  log6_ip_ttl_type_name("rr", server, ttl, type, name);
  log_space();
  for (i = 0; i < len; ++i) {
    log_hex((byte_t)buf[i]);
    if (i > 30) {
      log_string("...");
      break;
    }
  }
  log_line();
}
