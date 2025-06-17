#include <nemo/byte.h>
#include <nemo/scan.h>

#include "dns.h"
#include "dd.h"
#include "die.h"

/*
  assume for ipv4:

  123.123.123.123 and example.com

  123.123.123.123.example.com
*/

int dd4(const dns_domain *q, const dns_domain *base, ip4_address *ip)
{
/*
  static dns_domain t = DNS_DOMAIN;
  byte_t str[4];
  unsigned int len;
  unsigned int j;
  unsigned int x;

  if (!dns_domain_copy(&t, q)) die_nomem();

  for (j = 0; ; ++j) {
    if (dns_domain_equal(&t, base)) return (int)j;
    if (j >= 4) return -1;
    len = dns_domain_labellength(&t);
    if (!len) return -1;
    if (len >= 4) return -1;
    byte_copy(str, len, t.data + 1);
    str[len] = '\0';
    if (scan_uint(str, &x) != len) return -1;
    if (x > 255) return -1;
    ip->d[j] = (byte_t)x;
    dns_domain_drop1label(&t);
  }
*/
  dns_domain d;
  byte_t str[4];
  unsigned int len;
  unsigned int j;
  unsigned int v;

  d = *q;
  for (j = 0; ; ++j) {
    if (dns_domain_equal(&d, base)) return (int)j;
    if (j >= 4) return -1;
    len = d.data[0];
    if (!len) return -1;
    if (len >= 4) return -1;
    byte_copy(str, len, d.data + 1);
    str[len] = '\0';
    if (scan_uint(str, &v) != len) return -1;
    if (v > 255) return -1;
    ip->d[j] = (byte_t)v;
    len++;  /* include 'label length' byte */
    d.data += len;  /* simulate drop label, pt 1 */
    d.len -= len;  /* simulate drop label, pt 2 */
  }
}
