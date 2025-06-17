#include "dns.h"

unsigned int mxip4_vector_append(register mxip4_vector *vector, register const ip4_address *ip, unsigned int pref)
{
  register mxip4_data *cur;

  if (!mxip4_vector_readyplus(vector, 1)) return 0;
  cur = &(vector->va[vector->len]);
  ip4_copy(&cur->ip, ip);
  cur->pref = pref;
  vector->len++;  /* only do this after success */
  return 1;
}
