#include "dns.h"

struct dns6_transmit dns6_resolve_tx = DNS6_TRANSMIT;  /* global */

int dns6_resolve(const dns_domain *qname, const dns_type *qtype)
{
  static ip6_vector servers = IP6_VECTOR;

  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (dns_resolve_conf_ip6(&servers) < 0) return -1;
  if (dns6_transmit_start(&dns6_resolve_tx, &servers, 1, qname, qtype, null_ip6) < 0) return -1;
  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);
    dns6_transmit_io(&dns6_resolve_tx, x, &deadline);
    iopause(x, 1, &deadline, &stamp);
    r = dns6_transmit_get(&dns6_resolve_tx, x, &stamp);
    if (r < 0) return -1;
    if (r) return 0;
  }
}
