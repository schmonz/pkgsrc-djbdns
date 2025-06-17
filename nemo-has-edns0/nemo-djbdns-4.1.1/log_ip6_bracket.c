#include "dns.h"
#include "log.h"

void log_ip6_bracket(const ip6_address *ip)
{
  log_char('[');
  log_ip6(ip);
  log_char(']');
}
