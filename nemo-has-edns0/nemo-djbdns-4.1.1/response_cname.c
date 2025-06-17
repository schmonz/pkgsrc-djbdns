#include "response.h"

unsigned int response_cname(const dns_domain *cname, const dns_domain *dname, uint32_t ttl)
{
  if (!response_rr_start(cname, dns_t_cname, ttl)) return 0;
  if (!response_addname(dname)) return 0;
  response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
  return 1;
}
