#ifndef NEMO_ROOTS_H
#define NEMO_ROOTS_H

unsigned int	roots4(const dns_domain *q, ip4_vector *servers);
unsigned int	roots4_same(const dns_domain *d1, const dns_domain *d2);
void		roots4_init(void);

unsigned int	roots6(const dns_domain *q, ip6_vector *servers);
unsigned int	roots6_same(const dns_domain *d1, const dns_domain *d2);
void		roots6_init(void);

#endif
