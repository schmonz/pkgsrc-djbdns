#include <nemo/stdint.h>
#include <nemo/uint16.h>
#include <nemo/error.h>

#include "dns.h"

int dns4_ip4(ip4_vector *out, const stralloc *fqdn)
{
  static stralloc tmp = STRALLOC;
  static dns_domain qname = DNS_DOMAIN;
  ip4_address ip;

  if (!ip4_vector_erase(out)) return -1;

  if (stralloc_len(fqdn) > 255) {  /* avoid bad FQDN */
    errno = error_proto;
    return -1;
  }
  if (!stralloc_copy(&tmp, fqdn)) return -1;
  if (!stralloc_0(&tmp)) return -1;

  if (ip4_scan(&ip, tmp.s) == fqdn->len || ip4_scanbracket(&ip, tmp.s) == fqdn->len) {
    if (!ip4_vector_append(out, &ip)) return -1;
    return 0;
  }

  if (!dns_domain_fromdot(&qname, fqdn->s, fqdn->len)) return -1;

  if (dns4_resolve(&qname, dns_t_a) < 0) return -1;
  if (dns_ip4_packet(out, dns4_resolve_tx.packet, dns4_resolve_tx.packetlen) < 0) return -1;
  dns4_transmit_free(&dns4_resolve_tx);

  return 0;
}
