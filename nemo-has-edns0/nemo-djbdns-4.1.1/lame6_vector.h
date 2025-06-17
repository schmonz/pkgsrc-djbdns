#ifndef LAME6_VECTOR_H
#define LAME6_VECTOR_H

typedef struct {
  dns_domain control;
  ip6_address ip;
  time_t expire;
} lame6_data;

#define LAME6_DATA { DNS_DOMAIN,IP6_ADDRESS,0 }

typedef struct {
  lame6_data *va;
  unsigned int len;
  unsigned int a;
} lame6_vector;

#define LAME6_VECTOR { 0,0,0 }

void	lame6_data_init(lame6_data *x);
void	lame6_data_free(lame6_data *x);

static inline void lame6_vector_init(register lame6_vector *v)
{
  v->va = 0;
  v->a = v->len = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int	lame6_vector_realloc(lame6_vector *v, unsigned int n);
unsigned int	lame6_vector_alloc(lame6_vector *v, unsigned int n);

static inline unsigned int lame6_vector_ready(register lame6_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return lame6_vector_realloc(v, n);
  }
  return lame6_vector_alloc(v, n);
}

static inline unsigned int lame6_vector_readyplus(register lame6_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return lame6_vector_realloc(v, n);
  }
  return lame6_vector_alloc(v, n);
}

unsigned int	lame6_vector_append(lame6_vector *v, const lame6_data *a);
void		lame6_vector_purge(lame6_vector *v, time_t t);
/*
  return length, safely
*/
static inline unsigned int lame6_vector_len(register const lame6_vector *v)
{
  if (v->va) return v->len;
  return 0;
}

#endif  /* LAME6_VECTOR_H */
