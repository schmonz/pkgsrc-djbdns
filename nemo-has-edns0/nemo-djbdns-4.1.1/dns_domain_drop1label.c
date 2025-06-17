#include <nemo/byte.h>

#include "dns.h"

unsigned int dns_domain_drop1label(dns_domain *d)
{
  unsigned int i;
  unsigned int len;

  if (!dns_domain_active(d)) return 0;
  i = dns_domain_labellength(d);
  if (!i) return 0;
  i++;
  len = d->len - i;
  byte_copy(d->data, len, d->data + i);  /* shift left */
  d->len = len;
  return 1;
}
