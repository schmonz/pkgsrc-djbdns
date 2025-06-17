#include "dns.h"
#include "log.h"

void log6_rejected_packet(const ip6_address *ip, unsigned int port)
{
  log_prefix("rejected packet");
  log_ip6_bracket(ip);
  log_colon();
  log_number(port);
  log_line();
}
