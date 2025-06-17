#include "dns.h"

struct dns4_transmit dns4_resolve_tx = DNS4_TRANSMIT;  /* global */

int dns4_resolve(const dns_domain *qname, const dns_type *qtype)
{
  static ip4_vector servers = IP4_VECTOR;

  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (dns_resolve_conf_ip4(&servers) < 0) return -1;
  if (dns4_transmit_start(&dns4_resolve_tx, &servers, 1, qname, qtype, null_ip4) < 0) return -1;
  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);
    dns4_transmit_io(&dns4_resolve_tx, x, &deadline);
    iopause(x, 1, &deadline, &stamp);
    r = dns4_transmit_get(&dns4_resolve_tx, x, &stamp);
    if (r < 0) return -1;
    if (r) return 0;
  }
}
