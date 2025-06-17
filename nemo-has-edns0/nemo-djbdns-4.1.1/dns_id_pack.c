#include "dns.h"

void dns_id_pack(const dns_id *in, void *out)
{
  register uint16_t i;
  register byte_t *x;
  i = in->d;
  x = out;
  x++;
  *x-- = (byte_t)(i & 255);
  *x = (byte_t)(i >> 8);
}
