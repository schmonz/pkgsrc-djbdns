#include <nemo/byte.h>
#include <nemo/fmt.h>

#include "dns.h"
#include "die.h"

int dns_name4_domain(dns_domain *dn, const ip4_address *ip)
{
  byte_t data[256];
  byte_t *name;
  const byte_t *d;
  unsigned int name_len;
  unsigned int i;

  name = data;
  name_len = 0;
  d = ip->d + 3;
  i = fmt_ulong(name + 1, (unsigned long)(*d));
  d--;
  *name = (byte_t)i++;
  name += i;
  name_len += i;
  i = fmt_ulong(name + 1, (unsigned long)(*d));
  d--;
  *name = (byte_t)i++;
  name += i;
  name_len += i;
  i = fmt_ulong(name + 1, (unsigned long)(*d));
  d--;
  *name = (byte_t)i++;
  name += i;
  name_len += i;
  i = fmt_ulong(name + 1, (unsigned long)(*d));
  *name = (byte_t)i++;
  name += i;
  name_len += i;
  byte_copy(name, 14, "\007in-addr\004arpa\000");
  name_len += 14;
  if (!dns_domain_copyb(dn, data, name_len)) return -1;
  return 0;
}
