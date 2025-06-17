#include "dns.h"
#include "log.h"

void log6_ignore_referral(const ip6_address *server, const dns_domain *control, const dns_domain *referral)
{
  log_prefix("ignored-referral");
  log_ip6(server);
  log_space();
  log_domain(control);
  log_space();
  log_domain(referral);
  log_line();
}
