#include <nemo/alloc.h>
#include <nemo/byte.h>

#include "dns.h"
#include "query_vector.h"

unsigned int query_data_erase(query_data *x)
{
  if (!dns_domain_erase(&x->owner)) return 0;
  dns_type_zero(&x->type);
  return 1;
}

static void init_data(query_data va[], unsigned int i, unsigned int n)
{
  register query_data *x;
  while (i < n) {
    x = &va[i];
    dns_domain_init(&x->owner);
    i++;
  }
}

unsigned int query_vector_ready(register query_vector *v, register unsigned int n)
{
  register unsigned int i;
  if (v->va) {
    i = v->a;
    if (n > i) {
      n += 30 + (n >> 3);  /* add wiggle room */
      if (alloc_re((void **)&(v->va), i * sizeof(query_data), (v->a = n) * sizeof(query_data))) {
        init_data(v->va, i, n);
        return 1;
      }
      v->a = i;
      return 0;
    }
    return 1;
  }
  v->len = 0;
  if ((v->va = (query_data *) alloc((v->a = n) * sizeof(query_data)))) {
    init_data(v->va, 0, n);
    return 1;
  }
  return 0;
}

unsigned int query_vector_readyplus(register query_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
  }
  return query_vector_ready(v, n);
}

unsigned int query_vector_append(register query_vector *v, const query_data *a)
{
  register query_data *cur;

  if (!query_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!dns_domain_copy(&cur->owner, &a->owner)) return 0;
  dns_type_copy(&cur->type, &a->type);
  v->len++;  /* only do this after success */
  return 1;
}
