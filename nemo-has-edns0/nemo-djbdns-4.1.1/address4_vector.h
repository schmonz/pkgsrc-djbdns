#ifndef NEMO_ADDRESS4_VECTOR_H
#define NEMO_ADDRESS4_VECTOR_H

typedef struct {
  dns_domain name;
  ip4_address ip;
  char location[2];
} address4_data;

#define ADDRESS4_DATA { DNS_DOMAIN,IP4_ADDRESS,{'\0','\0'} }

typedef struct {
  address4_data *va;
  unsigned int len;
  unsigned int a;
} address4_vector;

#define ADDRESS4_VECTOR { 0,0,0 }

static inline void address4_vector_init(register address4_vector *v)
{
  v->va = 0;
  v->a = v->len = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int address4_vector_realloc(address4_vector *v, unsigned int n);
unsigned int address4_vector_alloc(address4_vector *v, unsigned int n);

static inline unsigned int address4_vector_ready(register address4_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return address4_vector_realloc(v, n);
  }
  return address4_vector_alloc(v, n);
}

static inline unsigned int address4_vector_readyplus(register address4_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return address4_vector_realloc(v, n);
  }
  return address4_vector_alloc(v, n);
}

unsigned int	address4_data_erase(address4_data *x);
unsigned int	address4_vector_append(address4_vector *av, const address4_data *a);
/*
  return length, safely
*/
static inline unsigned int address4_vector_len(register const address4_vector *v)
{
  if (v->va) return v->len;
  return 0;
}

#endif
