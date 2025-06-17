#include "dns.h"

void dns_type_pack(const dns_type *in, void *out)
{
  register uint16_t i;
  register byte_t *x;
  i = in->d;
  x = out;
  x++;
  *x-- = (byte_t)(i & 255);
  *x = (byte_t)(i >> 8);
}
