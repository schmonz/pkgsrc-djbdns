#include "dns.h"

struct dns4_transmit dns4_notify_tx = DNS4_TRANSMIT;  /* global */

int dns4_notify(const ip4_address *local_ip, const stralloc *domain, const ip4_address *server_ip)
{
  static dns_domain qname = DNS_DOMAIN;
  static ip4_vector servers = IP4_VECTOR;

  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (!ip4_vector_erase(&servers)) return -1;
  if (!ip4_vector_append(&servers, server_ip)) return -1;
  if (!dns_domain_fromdot(&qname, domain->s, domain->len)) return -1;
  if (dns4_transmit_start_notify(&dns4_notify_tx, &servers, &qname, local_ip) < 0) return -1;
  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);
    dns4_transmit_io(&dns4_notify_tx, x, &deadline);
    iopause(x, 1, &deadline, &stamp);
    r = dns4_transmit_get(&dns4_notify_tx, x, &stamp);
    if (r < 0) return -1;
    if (r) return 0;
  }
}
