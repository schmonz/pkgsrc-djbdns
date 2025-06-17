#include "dns.h"

unsigned int dns_type_equalb(const dns_type *qt, const void *d)
{
  register uint16_t result;
  register const byte_t *data;
  data = d;
  result = *data++;
  result = (uint16_t)(result << 8);
  result = (uint16_t)(result | *data);
  return result == qt->d;
}
