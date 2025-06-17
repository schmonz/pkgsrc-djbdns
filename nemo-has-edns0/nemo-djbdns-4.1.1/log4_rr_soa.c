#include <nemo/stdint.h>
#include <nemo/uint32.h>

#include "dns.h"
#include "log.h"

void log4_rr_soa(const ip4_address *server, const dns_domain *name, const dns_domain *n1, const dns_domain *n2, const byte_t misc[20], uint32_t ttl)
{
  uint32_t u;
  unsigned int i;

  log4_ip_ttl_type_name("rr", server, ttl, dns_t_soa, name);
  log_space();
  log_domain(n1);
  log_space();
  log_domain(n2);
  for (i = 0; i < 20; i += 4) {
    uint32_unpack_big(&u, misc + i);
    log_space();
    log_number(u);
  }
  log_line();
}
