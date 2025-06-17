#include <nemo/byte.h>
#include <nemo/error.h>

#include "dns.h"

unsigned int dns_domain_catb(dns_domain *out, const void *d, unsigned int len)
{
  unsigned int pos;
  pos = dns_domain_length(out) - 1;
  if ((pos + len) > 255) {
    errno = error_proto;
    return 0;
  }
  if (!d || !len) return 1;
  if (!dns_domain_readyplus(out, len - 1)) return 0;
  byte_copy(out->data + pos, len, d);
  out->len += len - 1;
  return 1;
}
