#include <nemo/alloc.h>

#include "dns.h"

unsigned int soa_vector_append(register soa_vector *v, const soa_data *a)
{
  register soa_data *cur;
  if (!soa_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!stralloc_copy(&cur->mname, &a->mname)) return 0;
  if (!stralloc_copy(&cur->rname, &a->rname)) return 0;
  cur->serial = a->serial;
  cur->refresh = a->refresh;
  cur->retry = a->retry;
  cur->expire = a->expire;
  cur->minimum = a->minimum;
  v->len++;  /* only do this after success */
  return 1;
}
