#include "dns.h"

struct dns6_transmit dns6_notify_tx = DNS6_TRANSMIT;  /* global */

int dns6_notify(const ip6_address *local_ip, const stralloc *domain, const ip6_address *server_ip)
{
  static dns_domain qname = DNS_DOMAIN;
  static ip6_vector servers = IP6_VECTOR;

  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (!ip6_vector_erase(&servers)) return -1;
  if (!ip6_vector_append(&servers, server_ip)) return -1;
  if (!dns_domain_fromdot(&qname, domain->s, domain->len)) return -1;
  if (dns6_transmit_start_notify(&dns6_notify_tx, &servers, &qname, local_ip) < 0) return -1;
  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);
    dns6_transmit_io(&dns6_notify_tx, x, &deadline);
    iopause(x, 1, &deadline, &stamp);
    r = dns6_transmit_get(&dns6_notify_tx, x, &stamp);
    if (r < 0) return -1;
    if (r) return 0;
  }
}
