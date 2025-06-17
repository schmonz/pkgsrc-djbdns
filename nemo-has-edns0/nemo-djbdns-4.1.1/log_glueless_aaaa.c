#include "dns.h"
#include "log.h"

void log_glueless_aaaa(const dns_domain *name, const dns_domain *control)
{
  log_prefix("glueless aaaa");
  log_domain(name);
  log_space();
  log_domain(control);
  log_line();
}
