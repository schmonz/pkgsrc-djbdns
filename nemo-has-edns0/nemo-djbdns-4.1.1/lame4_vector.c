#include <nemo/alloc.h>

#include "dns.h"
#include "lame4_vector.h"

#define	BASE 30

#define	DATA_SIZE sizeof(lame4_data)

void lame4_data_init(register lame4_data *x)
{
  dns_domain_init(&x->control);
  ip4_zero(&x->ip);
  x->expire = 0;
}

void lame4_data_free(register lame4_data *x)
{
  dns_domain_free(&x->control);
  lame4_data_init(x);
}

static void init_vector(register lame4_data va[], register unsigned int i, register unsigned int n)
{
  while (i < n) {
    lame4_data_init(&va[i]);
    i++;
  }
}

unsigned int lame4_vector_realloc(register lame4_vector *v, register unsigned int n)
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

unsigned int lame4_vector_alloc(register lame4_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  if ((v->va = (lame4_data *)alloc(v->a * DATA_SIZE))) {
    init_vector(v->va, 0, v->a);
    return 1;
  }
  return 0;
}

unsigned int lame4_vector_append(register lame4_vector *v, const lame4_data *a)
{
  register lame4_data *cur;
  if (!lame4_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!dns_domain_copy(&cur->control, &a->control)) return 0;
  ip4_copy(&cur->ip, &a->ip);
  cur->expire = a->expire;
  v->len++;  /* only do this after success */
  return 1;
}

void lame4_vector_purge(register lame4_vector *v, time_t t)
{
  register lame4_data *cur;
  register lame4_data *dest;
  register lame4_data *end;
  unsigned int count;

  count = 0;
  dest = cur = v->va;
  end = cur + v->len;
  while (cur < end) {
    if (cur->expire <= t) {  /* expired */
      dns_domain_free(&cur->control);
      lame4_data_init(cur);
      count++;
      cur++;
      continue;
    }
    if (!dest->expire) {  /* expired */
      *dest = *cur;  /* can only do this on zeroed dest */
      lame4_data_init(cur);  /* remove 2nd ref to control's data */
    }
    dest++;
    cur++;
  }
  v->len -= count;
}
