#include <nemo/stdint.h>
#include <nemo/uint16.h>
#include <nemo/error.h>

#include "dns.h"

int dns6_ip6(ip6_vector *out, const stralloc *fqdn)
{
  static stralloc tmp = STRALLOC;
  static dns_domain qname = DNS_DOMAIN;
  ip6_address ip;

  if (!ip6_vector_erase(out)) return -1;

  if (stralloc_len(fqdn) > 255) {  /* avoid bad FQDN */
    errno = error_proto;
    return -1;
  }
  if (!stralloc_copy(&tmp, fqdn)) return -1;
  if (!stralloc_0(&tmp)) return -1;

  if (ip6_scan(&ip, tmp.s) == fqdn->len || ip6_scanbracket(&ip, tmp.s) == fqdn->len) {
    if (!ip6_vector_append(out, &ip)) return -1;
    return 0;
  }

  if (!dns_domain_fromdot(&qname, fqdn->s, fqdn->len)) return -1;

  if (dns6_resolve(&qname, dns_t_aaaa) < 0) return -1;
  if (dns_ip6_packet(out, dns6_resolve_tx.packet, dns6_resolve_tx.packetlen) < 0) return -1;
  dns6_transmit_free(&dns6_resolve_tx);

  return 0;
}
