#ifndef NS_VECTOR_H
#define NS_VECTOR_H

typedef struct {
  dns_domain owner;
  dns_domain ns;
} ns_data;

#define NS_DATA { DNS_DOMAIN,DNS_DOMAIN }

typedef struct {
  ns_data *va;
  unsigned int len;
  unsigned int a;
} ns_vector;

#define NS_VECTOR { 0,0,0 }

static inline void ns_vector_init(register ns_vector *v)
{
  v->va = 0;
  v->a = v->len = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int ns_vector_realloc(ns_vector *v, unsigned int n);
unsigned int ns_vector_alloc(ns_vector *v, unsigned int n);

static inline unsigned int ns_vector_ready(register ns_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return ns_vector_realloc(v, n);
  }
  return ns_vector_alloc(v, n);
}

static inline unsigned int ns_vector_readyplus(register ns_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return ns_vector_realloc(v, n);
  }
  return ns_vector_alloc(v, n);
}

unsigned int	ns_data_erase(ns_data *x);
unsigned int	ns_vector_append(ns_vector *nsv, const ns_data *a);
/*
  return length, safely
*/
static inline unsigned int ns_vector_len(register const ns_vector *v)
{
  if (v->va) return v->len;
  return 0;
}

#endif  /* NS_VECTOR_H */
