#ifndef NEMO_RESPOND_H
#define NEMO_RESPOND_H

void initialize(void);
unsigned int respond4(const dns_domain *q, const dns_type *qtype, const ip4_address *ip, unsigned int udp_size, unsigned int flag_edns0);
unsigned int respond6(const dns_domain *q, const dns_type *qtype, const ip6_address *ip, unsigned int udp_size, unsigned int flag_edns0);

#endif
