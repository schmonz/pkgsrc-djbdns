#include "dns.h"
#include "log.h"

void log6_rejected_source_ip(const ip6_address *ip)
{
  log_prefix("rejected source-ip");
  log_ip6_bracket(ip);
  log_line();
}
