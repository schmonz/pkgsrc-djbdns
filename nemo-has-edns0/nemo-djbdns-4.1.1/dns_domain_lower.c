#include <nemo/byte.h>

#include "dns.h"

void dns_domain_lower(dns_domain *d)
{
  byte_lower(d->data, d->len);  /* safe since 63 < 'A' */
}
