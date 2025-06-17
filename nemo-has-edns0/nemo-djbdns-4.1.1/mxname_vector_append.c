#include "dns.h"

unsigned int mxname_vector_append(register mxname_vector *vector, const stralloc *name, unsigned int pref)
{
  register mxname_data *cur;

  if (!mxname_vector_readyplus(vector, 1)) return 0;
  cur = &(vector->va[vector->len]);
  cur->pref = pref;
  if (!stralloc_copy(&cur->sa, name)) return 0;
  vector->len++;  /* only do this after success */
  return 1;
}
