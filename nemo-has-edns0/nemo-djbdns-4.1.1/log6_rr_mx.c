#include <nemo/stdint.h>
#include <nemo/uint16.h>

#include "dns.h"
#include "log.h"

void log6_rr_mx(const ip6_address *server, const dns_domain *name, const dns_domain *mx, const byte_t pref[2], uint32_t ttl)
{
  uint16_t u;

  log6_ip_ttl_type_name("rr", server, ttl, dns_t_mx, name);
  log_space();
  uint16_unpack_big(&u, pref);
  log_number(u);
  log_space();
  log_domain(mx);
  log_line();
}
