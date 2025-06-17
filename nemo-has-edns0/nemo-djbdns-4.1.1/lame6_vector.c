#include <nemo/alloc.h>

#include "dns.h"
#include "lame6_vector.h"

#define	BASE 30

#define	DATA_SIZE sizeof(lame6_data)

void lame6_data_init(register lame6_data *x)
{
  dns_domain_init(&x->control);
  ip6_zero(&x->ip);
  x->expire = 0;
}

void lame6_data_free(register lame6_data *x)
{
  dns_domain_free(&x->control);
  lame6_data_init(x);
}

static void init_vector(register lame6_data va[], register unsigned int i, register unsigned int n)
{
  while (i < n) {
    lame6_data_init(&va[i]);
    i++;
  }
}

unsigned int lame6_vector_realloc(register lame6_vector *v, register unsigned int n)
{
  register unsigned int i;
  i = v->a;
  v->a = BASE + n + (n >> 3);
  if (alloc_re((void **)&(v->va), i * DATA_SIZE, v->a * DATA_SIZE)) {
    init_vector(v->va, i, v->a);
    return 1;
  }
  v->a = i;
  return 0;
}

unsigned int lame6_vector_alloc(register lame6_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  if ((v->va = (lame6_data *)alloc(v->a * DATA_SIZE))) {
    init_vector(v->va, 0, v->a);
    return 1;
  }
  return 0;
}

unsigned int lame6_vector_append(register lame6_vector *v, const lame6_data *a)
{
  register lame6_data *cur;
  if (!lame6_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!dns_domain_copy(&cur->control, &a->control)) return 0;
  ip6_copy(&cur->ip, &a->ip);
  cur->expire = a->expire;
  v->len++;  /* only do this after success */
  return 1;
}

void lame6_vector_purge(register lame6_vector *v, time_t t)
{
  register lame6_data *cur;
  register lame6_data *dest;
  register lame6_data *end;
  unsigned int count;

  count = 0;
  dest = cur = v->va;
  end = cur + v->len;
  while (cur < end) {
    if (cur->expire <= t) {  /* expired */
      dns_domain_free(&cur->control);
      lame6_data_init(cur);
      count++;
      cur++;
      continue;
    }
    if (!dest->expire) {  /* expired */
      *dest = *cur;  /* can only do this on zeroed dest */
      lame6_data_init(cur);  /* remove 2nd ref to control's data */
    }
    dest++;
    cur++;
  }
  v->len -= count;
}
