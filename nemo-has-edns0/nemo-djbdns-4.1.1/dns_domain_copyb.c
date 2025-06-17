#include <nemo/byte.h>
#include <nemo/error.h>

#include "dns.h"

unsigned int dns_domain_copyb(dns_domain *out, const void *d, unsigned int len)
{
  static const byte_t nullstr[] = "\0";
  const byte_t *buf;
  if (len > 255) {
    errno = error_proto;
    return 0;
  }
  buf = d;
  if (!buf || !len) {
    buf = nullstr;
    len = 1;
  }
  if (!dns_domain_ready(out, len)) return 0;
  byte_copy(out->data, len, buf);
  out->len = len;
  return 1;
}
