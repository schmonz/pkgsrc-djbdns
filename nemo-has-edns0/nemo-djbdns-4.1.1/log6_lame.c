#include "dns.h"
#include "log.h"
#include "lame6_servers.h"

void log6_lame(const ip6_address *server, const dns_domain *control, const dns_domain *referral)
{
  log_prefix("lame");
  log_ip6(server);
  log_space();
  log_domain(control);
  log_space();
  log_domain(referral);
  log_space();
  log_number(lame6_servers_count());
  log_line();
}
