#ifndef NEMO_DD_H
#define NEMO_DD_H

int dd4(const dns_domain *q, const dns_domain *base, ip4_address *ip);
int dd6(const dns_domain *q, const dns_domain *base, ip6_address *ip);

#endif
