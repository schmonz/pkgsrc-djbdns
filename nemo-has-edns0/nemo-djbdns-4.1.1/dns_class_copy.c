#include "dns.h"

void dns_class_copy(dns_class *out, const dns_class *in)
{
  *out = *in;
}
