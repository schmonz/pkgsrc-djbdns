#ifndef NEMO_QUERY_VECTOR_H
#define NEMO_QUERY_VECTOR_H

typedef struct {
  dns_domain owner;
  dns_type type;
} query_data;

#define QUERY_DATA { DNS_DOMAIN,DNS_TYPE }

typedef struct {
  query_data *va;
  unsigned int len;
  unsigned int a;
} query_vector;

#define QUERY_VECTOR { 0,0,0 }

unsigned int	query_data_erase(query_data *x);

unsigned int	query_vector_ready(query_vector *qv, unsigned int n);
unsigned int	query_vector_readyplus(query_vector *qv, unsigned int n);
unsigned int	query_vector_append(query_vector *qv, const query_data *a);

#endif
