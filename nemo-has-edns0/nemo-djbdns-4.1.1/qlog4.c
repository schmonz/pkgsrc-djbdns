#include "dns.h"
#include "qlog.h"

void qlog4(const ip4_address *ip, uint16_t port, const dns_id *id, const dns_domain *qname, const dns_type *qtype, const char *result)
{
  char misc[IP4_FMT];

  qlog_put(misc, ip4_fmt(ip, misc));
  qlog(port, id, qname, qtype, result);
}
