#include <nemo/stdint.h>
#include <nemo/byte.h>
#include <nemo/char.h>

#include "dns.h"
#include "die.h"

/*
  RFC3596:
    4321:0:1:2:3:4:567:89ab
  ->
    b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA.
    b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.INT. (deprecated)
*/

int dns_name6_domain(dns_domain *dn, const ip6_address *ip)
{
  byte_t data[256];
  byte_t *name;
  const byte_t *d;
  unsigned int i;

  name = data;
  d = ip->d + 15;
  for (i = 0; i < 16; i++) {
    *name++ = '\001';
    *name++ = (byte_t)char_hex_chars[*d & 15];
    *name++ = '\001';
    *name++ = (byte_t)char_hex_chars[*d >> 4];
    d--;
  }
  byte_copy(name, 10, "\003ip6\004arpa\000");
  if (!dns_domain_copyb(dn, data, 74)) return -1;
  return 0;
}
