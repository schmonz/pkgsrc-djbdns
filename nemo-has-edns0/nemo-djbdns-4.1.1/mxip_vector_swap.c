#include "dns.h"

void mxip_vector_swap(register mxip_vector *v, register unsigned int i, register unsigned int j)
{
  mxip_data tmp;
  if (i >= v->len) return;
  if (j >= v->len) return;
  tmp = v->va[i];
  v->va[i] = v->va[j];
  v->va[j] = tmp;
}
