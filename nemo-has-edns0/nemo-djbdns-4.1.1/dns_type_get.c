#include "dns.h"

unsigned int dns_type_get(const dns_type *in)
{
  return in->d;
}
