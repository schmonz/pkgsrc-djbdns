#include <nemo/byte.h>
#include <nemo/scan.h>

#include "dns.h"
#include "dd.h"
#include "die.h"

/*
  assume for ipv6:

  0123:4567:89ab:cdef:0123:4567:89ab:cdef and example.com

  0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.example.com
*/

int dd6(const dns_domain *q, const dns_domain *base, ip6_address *ip)
{
/*
  static dns_domain t = DNS_DOMAIN;
  byte_t str[2];
  unsigned int len;
  unsigned int i;
  unsigned int j;
  unsigned long x;

  if (!dns_domain_copy(&t, q)) die_nomem();

  i = 0;
  ip6_zero(ip);
  for (j = 0; ; ++j) {
    if (dns_domain_equal(&t, base)) return (int)j;
    if (j >= 32) return -1;
    len = dns_domain_labellength(&t);
    if (!len) return -1;
    if (len >= 2) return -1;
    byte_copy(str, len, t.data + 1);
    str[len] = '\0';
    if (scan_xlong(str, &x) != len) return -1;
    if (x > 15) return -1;
    if (!(j & 1)) {
      x <<= 4;
    }
    ip->d[i] |= (byte_t)x;
    dns_domain_drop1label(&t);
    if (j & 1) {
      i++;
    }
  }
*/
  dns_domain d;
  byte_t str[2];
  unsigned int j;
  unsigned long v;

  d = *q;
  str[1] = '\0';
  ip6_zero(ip);
  for (j = 0; ; ++j) {
    if (dns_domain_equal(&d, base)) return (int)j;
    if (j >= 32) return -1;
    if (d.data[0] != '\001') return -1;  /* all label lengths == 1 */
    str[0] = d.data[1];
    if (scan_xlong(str, &v) != 1) return -1;  /* hex encoded, single digit */
    if (!(j & 1)) {  /* index == 0,2,4,6,8,... */
      v <<= 4;
    }
    ip->d[j >> 1] |= (byte_t)v;
    d.data += 2;  /* simulate drop label, pt 1 */
    d.len -= 2;  /* simulate drop label, pt 2 */
  }
}
