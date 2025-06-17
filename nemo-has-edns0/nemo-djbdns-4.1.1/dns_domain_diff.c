#include "dns.h"

int dns_domain_diff(const dns_domain *dn1, const dns_domain *dn2)
{
  static sa_vector labels1 = SA_VECTOR;
  static sa_vector labels2 = SA_VECTOR;

  register unsigned int i;
  register unsigned int len1;
  register unsigned int len2;
  register int r;

  if (!dns_domain_labelparse(dn1, &labels1)) return 1;
  if (!dns_domain_labelparse(dn2, &labels2)) return -1;

  len1 = labels1.len;
  len2 = labels2.len;

  i = 0;
  while (len1 && len2) {
    r = stralloc_case_diff(&labels1.va[i], &labels2.va[i]);
    if (r) return r;
    ++i;
    --len1;
    --len2;
  }

  return (int)len1 - (int)len2;







}
