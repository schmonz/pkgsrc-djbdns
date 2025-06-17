#include "dns.h"

int dns6_txt(sa_vector *out, const stralloc *fqdn)
{
  static dns_domain q = DNS_DOMAIN;
  if (!dns_domain_fromdot(&q, fqdn->s, fqdn->len)) return -1;
  if (dns6_resolve(&q, dns_t_txt) < 0) return -1;
  if (dns_txt_packet(out, dns6_resolve_tx.packet, dns6_resolve_tx.packetlen, dns_t_txt) < 0) return -1;
  dns6_transmit_free(&dns6_resolve_tx);
  return 0;
}
