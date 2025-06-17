#include "dns.h"

unsigned int soa_vector_erase(register soa_vector *v)
{
  register unsigned int i;
  register unsigned int len;
  register soa_data *cur;
  if (!soa_vector_ready(v, 1)) return 0;
  len = v->len;
  for (i = 0; i < len; ++i) {
    cur = &(v->va[v->len]);
    if (!stralloc_erase(&cur->mname)) return 0;
    if (!stralloc_erase(&cur->rname)) return 0;
    cur->serial = 0;
    cur->refresh = 0;
    cur->retry = 0;
    cur->expire = 0;
    cur->minimum = 0;
  }
  v->len = 0;
  return 1;
}
