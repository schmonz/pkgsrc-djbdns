#ifndef SAFE_H
#define SAFE_H

unsigned int safe_packet_getname(const byte_t *buf, unsigned int len, unsigned int pos, dns_domain *d);

#endif /* SAFE_H */
