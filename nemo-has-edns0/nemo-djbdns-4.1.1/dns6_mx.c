#include "dns.h"

int dns6_mx(mxname_vector *out, const stralloc *fqdn)
{
  static dns_domain qname = DNS_DOMAIN;
  if (!dns_domain_fromdot(&qname, fqdn->s, fqdn->len)) return -1;
  if (dns6_resolve(&qname, dns_t_mx) < 0) return -1;
  if (dns_mx_packet(out, dns6_resolve_tx.packet, dns6_resolve_tx.packetlen) < 0) return -1;
  dns6_transmit_free(&dns6_resolve_tx);
  return 0;
}
