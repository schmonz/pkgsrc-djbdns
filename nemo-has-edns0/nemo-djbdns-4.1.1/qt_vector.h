#ifndef NEMO_QT_VECTOR_H
#define NEMO_QT_VECTOR_H

typedef struct {
  dns_domain owner;
  dns_domain control;
  ip4_address ip;
  dns_type type;
} qt4_data;

#define QT4_DATA { DNS_DOMAIN,DNS_DOMAIN,IP4_ADDRESS,DNS_TYPE }

typedef struct {
  qt4_data *va;
  unsigned int len;
  unsigned int a;
} qt4_vector;

#define QT4_VECTOR { 0,0,0 }

typedef struct {
  dns_domain owner;
  dns_domain control;
  ip6_address ip;
  dns_type type;
} qt6_data;

#define QT6_DATA { DNS_DOMAIN,DNS_DOMAIN,IP6_ADDRESS,DNS_TYPE }

typedef struct {
  qt6_data *va;
  unsigned int len;
  unsigned int a;
} qt6_vector;

#define QT6_VECTOR { 0,0,0 }

unsigned int	qt4_erase(qt4_data *x);

unsigned int	qt4_vector_ready(qt4_vector *qtv, unsigned int n);
unsigned int	qt4_vector_readyplus(qt4_vector *qtv, unsigned int n);
unsigned int	qt4_vector_append(qt4_vector *qtv, const qt4_data *a);

unsigned int	qt6_erase(qt6_data *x);

unsigned int	qt6_vector_ready(qt6_vector *qtv, unsigned int n);
unsigned int	qt6_vector_readyplus(qt6_vector *qtv, unsigned int n);
unsigned int	qt6_vector_append(qt6_vector *qtv, const qt6_data *a);

#endif
