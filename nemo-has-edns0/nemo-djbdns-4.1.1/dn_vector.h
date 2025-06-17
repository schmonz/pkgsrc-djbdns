#ifndef NEMO_DN_VECTOR_H
#define NEMO_DN_VECTOR_H

typedef struct {
  dns_domain *va;
  unsigned int len;
  unsigned int a;
} dn_vector;

#define DN_VECTOR { 0,0,0 }

unsigned int	dn_vector_ready(dn_vector *v, unsigned int n);
unsigned int	dn_vector_readyplus(dn_vector *v, unsigned int n);
unsigned int	dn_vector_cat(dn_vector *out, const dn_vector *in);
unsigned int	dn_vector_find(const dn_vector *v, const dns_domain *a);
unsigned int	dn_vector_append(dn_vector *v, const dns_domain *a);
unsigned int	dn_vector_erase(dn_vector *v);
void		dn_vector_remove(dn_vector *v, unsigned int i);
void		dn_vector_free(dn_vector *av);

#endif
