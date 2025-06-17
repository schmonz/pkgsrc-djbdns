#include <nemo/byte.h>

#include "dns.h"

int dns4_name4(sa_vector *out, const ip4_address *ip)
{
  static dns_domain qname = DNS_DOMAIN;
  if (dns_name4_domain(&qname, ip) < 0) return -1;
  if (dns4_resolve(&qname, dns_t_ptr) < 0) return -1;
  if (dns_name_packet(out, dns4_resolve_tx.packet, dns4_resolve_tx.packetlen) < 0) return -1;
  dns4_transmit_free(&dns4_resolve_tx);
  return 0;
}
