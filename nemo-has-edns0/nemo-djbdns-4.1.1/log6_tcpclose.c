#include "dns.h"
#include "log.h"

void log6_tcpclose(const ip6_address *client, unsigned int port)
{
  log_prefix("tcpclose");
  log_ip6_bracket(client);
  log_colon();
  log_number(port);
  log_line();
}
