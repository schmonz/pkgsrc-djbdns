#include "dns.h"

unsigned int mxname_vector_erase(register mxname_vector *v)
{
  register unsigned int i;
  register unsigned int len;
  if (!mxname_vector_ready(v, 1)) return 0;
  len = v->len;
  for (i = 0; i < len; ++i) {
    if (!stralloc_erase(&v->va[i].sa)) return 0;
  }
  v->len = 0;
  return 1;
}
