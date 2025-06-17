#ifndef IOQUERY6_H
#define IOQUERY6_H

#include "query6.h"

#define MAX_IOQUERY (MAX_UDP+MAX_TCP)

typedef struct _ioquery {
  dns_domain name;
  dns_type type;
  dns_domain control;
  struct dns6_transmit dt;
  iopause_fd *io;
  unsigned int edns0;  /* send OPT RR in request */
  unsigned int active;  /* active queries */
  query_ptr queries[MAX_IOQUERY];
  ioquery_ptr next;  /* next item in list, 0 == end */
} ioquery;

void	ioquery_setup(const ip6_address *ip_outgoing);
void	ioquery_io(ioquery *x, struct taia *deadline);
int	ioquery_get(ioquery *x, const struct taia *when);
void	ioquery_free(ioquery *x);

void	ioquery_servfail(ioquery *x);
void	ioquery_signal_clients(ioquery *x);

void	ioquery_remove_query(ioquery *x, const query *q);

ioquery	*ioquery_active_list_head(void);

unsigned int    ioquery_start(query *q,
                                ip6_vector *servers,
                                unsigned int flag_recursive,
                                unsigned int flag_edns0,
                                const dns_domain *name,
                                const dns_type *type,
                                const dns_domain *control);

void	ioquery_havepacket(ioquery *x);

#endif /* IOQUERY6_H */
