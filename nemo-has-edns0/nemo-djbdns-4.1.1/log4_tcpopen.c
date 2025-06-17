#include "dns.h"
#include "log.h"

void log4_tcpopen(const ip4_address *client, unsigned int port)
{
  log_prefix("tcpopen");
  log_ip4(client);
  log_colon();
  log_number(port);
  log_line();
}
