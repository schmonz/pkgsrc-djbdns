#include <nemo/byte.h>

#include "dns.h"

void dns_domain_pack(const dns_domain *in, void *out)
{
  byte_copy(out, in->len, in->data);
}
