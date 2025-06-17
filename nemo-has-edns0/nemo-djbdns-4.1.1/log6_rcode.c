#include <nemo/fmt.h>

#include "dns.h"
#include "log.h"

void log6_rcode(unsigned int rcode, const ip6_address *server, const dns_domain *name, const dns_type *type, uint32_t ttl)
{
  char fmtstr[FMT_ULONG];
  const char *x;

  x = dns_rcode_str(rcode);
  if (!x) {
    fmtstr[fmt_uint(fmtstr, rcode)] = '\0';
    x = fmtstr;
  }
  log6_ip_ttl_type_name(x, server, ttl, type, name);
  log_line();
}
