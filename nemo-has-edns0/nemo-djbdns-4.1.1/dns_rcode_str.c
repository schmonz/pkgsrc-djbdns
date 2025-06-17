/* Public domain. */

#include "dns.h"

#define X(v,s) if (rcode == (v)) return (s);

const char *dns_rcode_str(unsigned int rcode)
{
  X(DNS_RCODE_NOERROR, "noerror")
  X(DNS_RCODE_FORMERR, "formerr")
  X(DNS_RCODE_SERVFAIL, "servfail")
  X(DNS_RCODE_NXDOMAIN, "nxdomain")
  X(DNS_RCODE_NOTIMP, "notimp")
  X(DNS_RCODE_REFUSED, "refused")
  return 0;
}
