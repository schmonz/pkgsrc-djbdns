#include <nemo/alloc.h>

#include "dns.h"

#define	BASE 30

#define	DATA_SIZE sizeof(soa_data)

static void init_data(register soa_data v[], register unsigned int i, register unsigned int n)
{
  register soa_data *cur;
  while (i < n) {
    cur = &v[i];
    stralloc_init(&cur->mname);
    stralloc_init(&cur->rname);
    cur->serial = 0;
    cur->refresh = 0;
    cur->retry = 0;
    cur->expire = 0;
    cur->minimum = 0;
    i++;
  }
}

unsigned int soa_vector_realloc(register soa_vector *v, register unsigned int n)
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

unsigned int soa_vector_alloc(register soa_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  if ((v->va = (soa_data *) alloc(v->a * DATA_SIZE))) {
    init_data(v->va, 0, v->a);
    return 1;
  }
  return 0;
}
