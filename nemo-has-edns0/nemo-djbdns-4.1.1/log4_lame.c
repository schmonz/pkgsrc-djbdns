#include "dns.h"
#include "log.h"
#include "lame4_servers.h"

void log4_lame(const ip4_address *server, const dns_domain *control, const dns_domain *referral)
{
  log_prefix("lame");
  log_ip4(server);
  log_space();
  log_domain(control);
  log_space();
  log_domain(referral);
  log_space();
  log_number(lame4_servers_count());
  log_line();
}
