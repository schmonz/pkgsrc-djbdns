#include "dns.h"

void dns_type_unpack(dns_type *out, const void *in)
{
  register uint16_t result;
  register const byte_t *x;
  x = in;
  result = *x++;
  result = (uint16_t)(result << 8);
  result = (uint16_t)(result | *x);
  out->d = result;
}
