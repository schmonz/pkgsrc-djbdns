#include "dns.h"

unsigned int dns_class_diffb(const dns_class *qc, const void *d)
{
  register uint16_t result;
  register const byte_t *data;

  data = d;
  result = *data++;
  result = (uint16_t)(result << 8);
  result = (uint16_t)(result | *data);
  return result != qc->d;
}
