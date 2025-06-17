#include "dns.h"

unsigned int mxip6_vector_append(register mxip6_vector *vector, register const ip6_address *ip, unsigned int pref)
{
  register mxip6_data *cur;

  if (!mxip6_vector_readyplus(vector, 1)) return 0;
  cur = &(vector->va[vector->len]);
  ip6_copy(&cur->ip, ip);
  cur->pref = pref;
  vector->len++;  /* only do this after success */
  return 1;
}
