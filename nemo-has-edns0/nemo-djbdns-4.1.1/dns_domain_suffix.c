#include "dns.h"

unsigned int dns_domain_suffix(const dns_domain *big, const dns_domain *little)
{
/*
  static dns_domain tmp = DNS_DOMAIN;

  if (!dns_domain_copy(&tmp, big)) return 0;
  for (;;) {
    if (dns_domain_equal(&tmp, little)) return 1;
    if (!dns_domain_labellength(&tmp)) return 0;
    dns_domain_drop1label(&tmp);
  }
*/
  unsigned int len;
  dns_domain d;

  d = *big;
  for (;;) {
    if (dns_domain_equal(&d, little)) return 1;
    len = d.data[0];
    if (!len) return 0;
    len++;  /* include 'label length' byte */
    d.data += len;  /* simulate drop label, pt 1 */
    d.len -= len;  /* simulate drop label, pt 2 */
  }
}
