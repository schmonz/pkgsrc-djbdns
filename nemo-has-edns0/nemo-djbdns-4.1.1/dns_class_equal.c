#include "dns.h"

unsigned int dns_class_equal(const dns_class *qc1, const dns_class *qc2)
{
  return qc1->d == qc2->d;
}
