#include "dns.h"
#include "log.h"

void log4_drop_query(uint64_t query_number, unsigned int len, const ip4_address *client, unsigned int port, const dns_id *id, unsigned int loop_count)
{
  log_prefix("drop");
  log_number(query_number);
  log_space();
  log_number(len);
  log_space();
  log_ip4(client);
  log_colon();
  log_number(port);
  log_colon();
  log_id(id);
  log_space();
  log_number(loop_count);
  log_line();
  log_stats();
}
