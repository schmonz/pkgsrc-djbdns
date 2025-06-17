#include "dns.h"
#include "log.h"

void log6_tcpopen(const ip6_address *client, unsigned int port)
{
  log_prefix("tcpopen");
  log_ip6_bracket(client);
  log_colon();
  log_number(port);
  log_line();
}
