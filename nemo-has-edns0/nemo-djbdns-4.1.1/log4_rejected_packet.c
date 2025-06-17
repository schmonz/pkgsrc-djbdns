#include "dns.h"
#include "log.h"

void log4_rejected_packet(const ip4_address *ip, unsigned int port)
{
  log_prefix("rejected packet");
  log_ip4(ip);
  log_colon();
  log_number(port);
  log_line();
}
