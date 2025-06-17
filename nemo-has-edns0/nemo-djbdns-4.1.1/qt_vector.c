#include <nemo/alloc.h>
#include <nemo/byte.h>

#include "dns.h"
#include "qt_vector.h"

unsigned int qt4_erase(qt4_data *x)
{
  if (!dns_domain_erase(&x->owner)) return 0;
  if (!dns_domain_erase(&x->control)) return 0;
  ip4_zero(&x->ip);
  dns_type_zero(&x->type);
  return 1;
}

static void init4_data(qt4_data va[], unsigned int i, unsigned int n)
{
  register qt4_data *x;
  while (i < n) {
    x = &va[i];
    dns_domain_init(&x->owner);
    dns_domain_init(&x->control);
    ip4_zero(&x->ip);
    dns_type_zero(&x->type);
    i++;
  }
}

unsigned int qt4_vector_ready(register qt4_vector *v, register unsigned int n)
{
  register unsigned int i;
  if (v->va) {
    i = v->a;
    if (n > i) {
      n += 30 + (n >> 3);  /* add wiggle room */
      if (alloc_re((void **)&(v->va), i * sizeof(qt4_data), (v->a = n) * sizeof(qt4_data))) {
        init4_data(v->va, i, n);
        return 1;
      }
      v->a = i;
      return 0;
    }
    return 1;
  }
  v->len = 0;
  if ((v->va = (qt4_data *) alloc((v->a = n) * sizeof(qt4_data)))) {
    init4_data(v->va, 0, n);
    return 1;
  }
  return 0;
}

unsigned int qt4_vector_readyplus(register qt4_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
  }
  return qt4_vector_ready(v, n);
}

unsigned int qt4_vector_append(register qt4_vector *v, const qt4_data *a)
{
  register qt4_data *cur;

  if (!qt4_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!dns_domain_copy(&cur->owner, &a->owner)) return 0;
  if (!dns_domain_copy(&cur->control, &a->control)) return 0;
  ip4_copy(&cur->ip, &a->ip);
  dns_type_copy(&cur->type, &a->type);
  v->len++;  /* only do this after success */
  return 1;
}

unsigned int qt6_erase(qt6_data *x)
{
  if (!dns_domain_erase(&x->owner)) return 0;
  if (!dns_domain_erase(&x->control)) return 0;
  ip6_zero(&x->ip);
  dns_type_zero(&x->type);
  return 1;
}

static void init6_data(qt6_data va[], unsigned int i, unsigned int n)
{
  register qt6_data *x;
  while (i < n) {
    x = &va[i];
    dns_domain_init(&x->owner);
    dns_domain_init(&x->control);
    ip6_zero(&x->ip);
    dns_type_zero(&x->type);
    i++;
  }
}

unsigned int qt6_vector_ready(register qt6_vector *v, register unsigned int n)
{
  register unsigned int i;
  if (v->va) {
    i = v->a;
    if (n > i) {
      n += 30 + (n >> 3);  /* add wiggle room */
      if (alloc_re((void **)&(v->va), i * sizeof(qt6_data), (v->a = n) * sizeof(qt6_data))) {
        init6_data(v->va, i, n);
        return 1;
      }
      v->a = i;
      return 0;
    }
    return 1;
  }
  v->len = 0;
  if ((v->va = (qt6_data *) alloc((v->a = n) * sizeof(qt6_data)))) {
    init6_data(v->va, 0, n);
    return 1;
  }
  return 0;
}

unsigned int qt6_vector_readyplus(register qt6_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
  }
  return qt6_vector_ready(v, n);
}

unsigned int qt6_vector_append(register qt6_vector *v, const qt6_data *a)
{
  register qt6_data *cur;

  if (!qt6_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!dns_domain_copy(&cur->owner, &a->owner)) return 0;
  if (!dns_domain_copy(&cur->control, &a->control)) return 0;
  ip6_copy(&cur->ip, &a->ip);
  dns_type_copy(&cur->type, &a->type);
  v->len++;  /* only do this after success */
  return 1;
}
