#include "dns.h"

unsigned int mxip_vector_append6(register mxip_vector *vector, const mxip6_data *d)
{
  register mxip_data *cur;

  if (!mxip_vector_readyplus(vector, 1)) return 0;
  cur = &(vector->va[vector->len]);
  cur->pref = d->pref;
  cur->ipmode = 6;
  cur->ip.ip6 = d->ip;
  vector->len++;  /* only do this after success */
  return 1;
}
