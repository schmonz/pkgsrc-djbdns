#include <nemo/alloc.h>

#include "dns.h"

#define	BASE 30

#define	DATA_SIZE sizeof(mxname_data)

static void init_data(register mxname_data va[], register unsigned int i, register unsigned int n)
{
  while (i < n) {
    stralloc_init(&va[i].sa);
    i++;
  }
}

unsigned int mxname_vector_realloc(register mxname_vector *v, register unsigned int n)
{
  register unsigned int i;
  i = v->a;
  v->a = BASE + n + (n >> 3);
  if (alloc_re((void **)&(v->va), i * DATA_SIZE, v->a * DATA_SIZE)) {
    init_data(v->va, i, v->a);
    return 1;
  }
  v->a = i;
  return 0;
}

unsigned int mxname_vector_alloc(register mxname_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  if ((v->va = (mxname_data *)alloc(v->a * DATA_SIZE))) {
    init_data(v->va, 0, v->a);
    return 1;
  }
  return 0;
}
