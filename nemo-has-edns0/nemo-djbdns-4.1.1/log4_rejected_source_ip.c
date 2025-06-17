#include "dns.h"
#include "log.h"

void log4_rejected_source_ip(const ip4_address *ip)
{
  log_prefix("rejected source-ip");
  log_ip4(ip);
  log_line();
}
