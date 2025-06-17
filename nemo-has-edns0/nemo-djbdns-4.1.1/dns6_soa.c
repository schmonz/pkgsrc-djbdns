#include "dns.h"

int dns6_soa(soa_vector *out, const stralloc *fqdn)
{
  static dns_domain q = DNS_DOMAIN;
  if (!dns_domain_fromdot(&q, fqdn->s, fqdn->len)) return -1;
  if (dns6_resolve(&q, dns_t_soa) < 0) return -1;
  if (dns_soa_packet(out, dns6_resolve_tx.packet, dns6_resolve_tx.packetlen) < 0) return -1;
  dns6_transmit_free(&dns6_resolve_tx);
  return 0;
}
