#include "dns.h"

void dns_type_set(dns_type *out, unsigned int in)
{
  out->d = (uint16_t)in;
}
