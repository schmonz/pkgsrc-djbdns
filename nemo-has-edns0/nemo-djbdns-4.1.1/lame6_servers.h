#ifndef NEMO_LAME6_SERVERS_H
#define NEMO_LAME6_SERVERS_H

#include "lame6_vector.h"

#define LAME_TTL 1800

unsigned int	lame6_servers_count(void);
void		lame6_servers_add(const dns_domain *control, const ip6_address *server, uint32_t ttl);
void		lame6_servers_prune(const dns_domain *control, ip6_vector *servers);

#endif
