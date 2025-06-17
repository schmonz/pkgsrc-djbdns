#include "dns.h"

/* XXX: sort servers by configurable notion of closeness? */
/* XXX: pay attention to competence of each server? */

void dns_sortip6(ip6_vector *v)
{
  unsigned int i;
  unsigned int n;

  n = v->len;
  while (n > 1) {
    i = dns_random(n);
    --n;
    ip6_vector_swap(v, i, n);
  }
}
