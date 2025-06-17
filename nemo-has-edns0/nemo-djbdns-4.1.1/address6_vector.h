#ifndef NEMO_ADDRESS6_VECTOR_H
#define NEMO_ADDRESS6_VECTOR_H

typedef struct {
  dns_domain name;
  ip6_address ip;
  char location[2];
} address6_data;

#define ADDRESS6_DATA { DNS_DOMAIN,IP6_ADDRESS,{'\0','\0'} }

typedef struct {
  address6_data *va;
  unsigned int len;
  unsigned int a;
} address6_vector;

#define ADDRESS6_VECTOR { 0,0,0 }

static inline void address6_vector_init(register address6_vector *v)
{
  v->va = 0;
  v->a = v->len = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int address6_vector_realloc(address6_vector *v, unsigned int n);
unsigned int address6_vector_alloc(address6_vector *v, unsigned int n);

static inline unsigned int address6_vector_ready(register address6_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return address6_vector_realloc(v, n);
  }
  return address6_vector_alloc(v, n);
}

static inline unsigned int address6_vector_readyplus(register address6_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return address6_vector_realloc(v, n);
  }
  return address6_vector_alloc(v, n);
}

unsigned int	address6_data_erase(address6_data *x);
unsigned int	address6_vector_append(address6_vector *av, const address6_data *a);

/*
  return length, safely
*/
static inline unsigned int address6_vector_len(register const address6_vector *v)
{
  if (v->va) return v->len;
  return 0;
}

#endif
