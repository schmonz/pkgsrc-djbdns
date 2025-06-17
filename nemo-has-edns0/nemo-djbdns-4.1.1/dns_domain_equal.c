#include <nemo/byte.h>

#include "dns.h"

unsigned int dns_domain_equal(const dns_domain *dn1, const dns_domain *dn2)
{
  unsigned int len;
  len = dns_domain_length(dn1);
  if (len != dns_domain_length(dn2)) return 0;
  if (byte_case_diff(dn1->data, len, dn2->data)) return 0;  /* safe since 63 < 'A' */
  return 1;
}
