#include "dns.h"

void mxname_vector_swap(register mxname_vector *v, register unsigned int i, register unsigned int j)
{
  mxname_data tmp;
  if (i >= v->len) return;
  if (j >= v->len) return;
  tmp = v->va[i];
  v->va[i] = v->va[j];
  v->va[j] = tmp;
}
