#include "dns.h"
#include "qlog.h"

void qlog6(const ip6_address *ip, uint16_t port, const dns_id *id, const dns_domain *qname, const dns_type *qtype, const char *result)
{
  char misc[IP6_FMT];

  qlog_put("[", 1);
  qlog_put(misc, ip6_fmt(ip, misc));
  qlog_put("]", 1);
  qlog(port, id, qname, qtype, result);
}
