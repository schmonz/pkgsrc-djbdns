#include "dns.h"

unsigned int dns_domain_suffixpos(const dns_domain *big, const dns_domain *little)
{
  unsigned int len;
  dns_domain d;
  d = *big;
  for (;;) {
    if (dns_domain_equal(&d, little)) return (unsigned int)(d.data - big->data);
    len = d.data[0];
    if (!len) return 0;
    len++;  /* include 'label length' byte */
    d.data += len;  /* simulate drop label, pt 1 */
    d.len -= len;  /* simulate drop label, pt 2 */
  }
}
