#include <nemo/alloc.h>

#include "dns.h"

void dns_domain_free(dns_domain *dn)
{
  if (dn->data) {
    alloc_free(dn->data);
    dn->data = 0;
    dn->len = dn->a = 0;
  }
}
