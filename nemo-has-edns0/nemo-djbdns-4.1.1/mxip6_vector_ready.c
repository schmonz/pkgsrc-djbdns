#include <nemo/alloc.h>

#include "dns.h"

#define	BASE 30

#define	DATA_SIZE sizeof(mxip6_data)

unsigned int mxip6_vector_realloc(register mxip6_vector *v, register unsigned int n)
{
  register unsigned int i;
  i = v->a;
  v->a = BASE + n + (n >> 3);
  if (alloc_re((void **)&(v->va), i * DATA_SIZE, v->a * DATA_SIZE)) return 1;
  v->a = i;
  return 0;
}

unsigned int mxip6_vector_alloc(register mxip6_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  return !!(v->va = (mxip6_data *)alloc(v->a * DATA_SIZE));
}
