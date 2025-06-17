#include <nemo/alloc.h>

#include "dns.h"
#include "ns_vector.h"

#define	BASE 30

#define	DATA_SIZE sizeof(ns_data)

static void init_data(register ns_data va[], register unsigned int i, register unsigned int n)
{
  register ns_data *x;
  while (i < n) {
    x = &va[i];
    dns_domain_init(&x->owner);
    dns_domain_init(&x->ns);
    i++;
  }
}

unsigned int ns_vector_realloc(register ns_vector *v, register unsigned int n)
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

unsigned int ns_vector_alloc(register ns_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  if ((v->va = (ns_data *)alloc(v->a * DATA_SIZE))) {
    init_data(v->va, 0, v->a);
    return 1;
  }
  return 0;
}

unsigned int ns_data_erase(ns_data *x)
{
  if (!dns_domain_erase(&x->owner)) return 0;
  if (!dns_domain_erase(&x->ns)) return 0;
  return 1;
}

unsigned int ns_vector_append(register ns_vector *v, const ns_data *a)
{
  register ns_data *cur;
  if (!ns_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!dns_domain_copy(&cur->owner, &a->owner)) return 0;
  if (!dns_domain_copy(&cur->ns, &a->ns)) return 0;
  v->len++;  /* only do this after success */
  return 1;
}
