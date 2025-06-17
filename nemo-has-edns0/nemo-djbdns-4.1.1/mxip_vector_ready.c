#include <nemo/alloc.h>

#include "dns.h"

#define	BASE 30

#define	DATA_SIZE sizeof(mxip_data)

unsigned int mxip_vector_realloc(register mxip_vector *v, register unsigned int n)
{
  register unsigned int i;
  i = v->a;
  v->a = BASE + n + (n >> 3);
  if (alloc_re((void **)&(v->va), i * DATA_SIZE, v->a * DATA_SIZE)) return 1;
  v->a = i;
  return 0;
}

unsigned int mxip_vector_alloc(register mxip_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  return !!(v->va = (mxip_data *)alloc(v->a * DATA_SIZE));
}
