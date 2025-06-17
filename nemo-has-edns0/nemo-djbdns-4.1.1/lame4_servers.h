#ifndef NEMO_LAME4_SERVERS_H
#define NEMO_LAME4_SERVERS_H

#include "lame4_vector.h"

#define LAME_TTL 1800

unsigned int	lame4_servers_count(void);
void		lame4_servers_add(const dns_domain *control, const ip4_address *server, uint32_t ttl);
void		lame4_servers_prune(const dns_domain *control, ip4_vector *servers);

#endif
