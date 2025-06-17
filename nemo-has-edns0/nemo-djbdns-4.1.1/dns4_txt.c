#include "dns.h"

int dns4_txt(sa_vector *out, const stralloc *fqdn)
{
  static dns_domain q = DNS_DOMAIN;
  if (!dns_domain_fromdot(&q, fqdn->s, fqdn->len)) return -1;
  if (dns4_resolve(&q, dns_t_txt) < 0) return -1;
  if (dns_txt_packet(out, dns4_resolve_tx.packet, dns4_resolve_tx.packetlen, dns_t_txt) < 0) return -1;
  dns4_transmit_free(&dns4_resolve_tx);
  return 0;
}
