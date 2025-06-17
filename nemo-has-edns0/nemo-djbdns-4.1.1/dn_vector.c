#include <nemo/alloc.h>
#include <nemo/byte.h>

#include "dns.h"
#include "dn_vector.h"

#define	BASE 10

#define	DATA_SIZE sizeof(dns_domain)

static void init_data(dns_domain v[], unsigned int i, unsigned int n)
{
  while (i < n) {
    dns_domain_init(&v[i]);
    i++;
  }
}

static unsigned int dn_vector_realloc(register dn_vector *v, register unsigned int n)
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

static unsigned int dn_vector_alloc(register dn_vector *v, register unsigned int n)
{
  v->len = 0;
  v->a = BASE + n + (n >> 3);
  if ((v->va = (dns_domain *)alloc(v->a * DATA_SIZE))) {
    init_data(v->va, 0, v->a);
    return 1;
  }
  return 0;
}

unsigned int dn_vector_ready(register dn_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return dn_vector_realloc(v, n);
  }
  return dn_vector_alloc(v, n);
}

unsigned int dn_vector_readyplus(register dn_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
  }
  return dn_vector_ready(v, n);
}

unsigned int dn_vector_append(register dn_vector *v, const dns_domain *a)
{
  register dns_domain *cur;

  if (!dn_vector_readyplus(v, 1)) return 0;
  cur = &(v->va[v->len]);
  if (!dns_domain_copy(cur, a)) return 0;
  v->len++;  /* only do this after success */
  return 1;
}
/*
unsigned int dn_vector_cat(dn_vector *out, const dn_vector *in)
{
  register unsigned int i;
  unsigned int len;

  if (!in->va) return 1;
  len = in->len;
  for (i = 0; i < len; ++i) {
    if (!dn_vector_append(out, &(in->va[i]))) return 0;
  }
  return 1;
}
*/
void dn_vector_free(register dn_vector *v)
{
  unsigned int i;
  unsigned int len;

  if (!v->va) return;
  len = v->len;
  for (i = 0; i < len; ++i) {
    dns_domain_free(&(v->va[i]));
  }
  alloc_free(v->va);
  v->va = 0;
  v->a = v->len = 0;
}

/*
  remove element 'i' by shuffle down,
  then shorten length by 1
*/
void dn_vector_remove(register dn_vector *v, register unsigned int i)
{
  register unsigned int last;

  if (!(v->len)) return;  /* zero length, nothing to do */
  last = v->len--;
  dns_domain_free(&v->va[i]);
  while (i < last) {
    v->va[i] = v->va[i + 1];
    i++;
  }
  dns_domain_init(&v->va[i]);
}

unsigned int dn_vector_find(const dn_vector *v, const dns_domain *name)
{
  register unsigned int i;

  for (i = 0; i < v->len; ++i) {
    if (dns_domain_equal(&(v->va[i]), name)) return 1;
  }
  return 0;
}

unsigned int dn_vector_erase(register dn_vector *v)
{
  register unsigned int i;
  register unsigned int len;

  if (!dn_vector_ready(v, 1)) return 0;

  len = v->len;
  for (i = 0; i < len; ++i) {
    if (!dns_domain_erase(&(v->va[i]))) return 0;
  }
  v->len = 0;
  return 1;
}
