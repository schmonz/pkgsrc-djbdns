#include <nemo/error.h>

#include "dns.h"
#include "die.h"
#include "safe.h"

unsigned int safe_packet_getname(const byte_t *buf, unsigned int len, unsigned int pos, dns_domain *d)
{
  register unsigned int r;
  r = dns_packet_getname(buf, len, pos, d);
  if (!r && (errno == error_nomem)) die_nomem();
  return r;
}
