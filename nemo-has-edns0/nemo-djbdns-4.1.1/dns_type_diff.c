#include "dns.h"

unsigned int dns_type_diff(const dns_type *qt1, const dns_type *qt2)
{
  return qt1->d != qt2->d;
}
