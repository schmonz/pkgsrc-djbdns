#ifndef LAME4_VECTOR_H
#define LAME4_VECTOR_H

typedef struct {
  dns_domain control;
  ip4_address ip;
  time_t expire;
} lame4_data;

#define LAME4_DATA { DNS_DOMAIN,IP4_ADDRESS,0 }

typedef struct {
  lame4_data *va;
  unsigned int len;
  unsigned int a;
} lame4_vector;

#define LAME4_VECTOR { 0,0,0 }

void	lame4_data_init(lame4_data *x);
void	lame4_data_free(lame4_data *x);

static inline void lame4_vector_init(register lame4_vector *v)
{
  v->va = 0;
  v->a = v->len = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int	lame4_vector_realloc(lame4_vector *v, unsigned int n);
unsigned int	lame4_vector_alloc(lame4_vector *v, unsigned int n);

static inline unsigned int lame4_vector_ready(register lame4_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return lame4_vector_realloc(v, n);
  }
  return lame4_vector_alloc(v, n);
}

static inline unsigned int lame4_vector_readyplus(register lame4_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return lame4_vector_realloc(v, n);
  }
  return lame4_vector_alloc(v, n);
}

unsigned int	lame4_vector_append(lame4_vector *v, const lame4_data *a);
void		lame4_vector_purge(lame4_vector *v, time_t t);
/*
  return length, safely
*/
static inline unsigned int lame4_vector_len(register const lame4_vector *v)
{
  if (v->va) return v->len;
  return 0;
}

#endif  /* LAME4_VECTOR_H */
