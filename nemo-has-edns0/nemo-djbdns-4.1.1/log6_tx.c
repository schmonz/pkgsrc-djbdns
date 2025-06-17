#include "dns.h"
#include "log.h"

void log6_tx(uint64_t query_number, const dns_domain *qname, const dns_type *qtype, const dns_domain *control, const ip6_vector *servers)
{
  unsigned int i;

  log_prefix("tx");
  log_number(query_number);
  log_string(" io ");
  log_type(qtype);
  log_space();
  log_domain(qname);
  log_space();
  log_domain(control);
  for (i = 0; i < servers->len; i++) {
    log_space();
    log_ip6(&servers->va[i]);
  }
  log_line();
}
