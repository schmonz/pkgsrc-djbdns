#include "dns.h"

unsigned int mxip_vector_cat6(mxip_vector *out, const mxip6_vector *in)
{
  register unsigned int i;
  unsigned int len;

  if (!in->va) return 1;
  len = in->len;
  for (i = 0; i < len; ++i) {
    if (!mxip_vector_append6(out, &(in->va[i]))) return 0;
  }
  return 1;
}
