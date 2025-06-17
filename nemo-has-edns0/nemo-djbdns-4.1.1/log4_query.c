#include "dns.h"
#include "log.h"

void log4_query(uint64_t query_number, const ip4_address *client, unsigned int port, const dns_id *id, const dns_domain *qname, const dns_type *qtype, unsigned int flag_edns0, unsigned int udp_size)
{
  log_prefix("query");
  log_number(query_number);
  log_space();
  log_ip4(client);
  log_colon();
  log_number(port);
  log_colon();
  log_id(id);
  log_space();
  log_type(qtype);
  log_space();
  log_domain(qname);
  log_space();
  log_number(flag_edns0);
  log_space();
  log_number(udp_size);
  log_line();
  /* log_stats(); */
}
