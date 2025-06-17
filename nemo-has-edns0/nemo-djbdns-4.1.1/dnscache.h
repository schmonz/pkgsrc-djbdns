#ifndef DNSCACHE_H
#define DNSCACHE_H

#include "dns.h"

#define MAX_LOOP	128

#define MAX_UDP		200
#define MAX_TCP		20

#define MAX_ALIAS	16

#define IO_TTL		120

typedef struct _ioquery *ioquery_ptr;
typedef struct _client *client_ptr;
typedef struct _query *query_ptr;

unsigned int	packetquery(const byte_t *buf, unsigned int len, dns_domain *qname, dns_type *qtype, dns_class *qclass, dns_id *id, unsigned int *flag_edns0, unsigned int *udp_size);
unsigned int	global_ip4(const dns_domain *name, ip4_address *ip);
unsigned int	global_ip6(const dns_domain *name, ip6_address *ip);

extern uint64_t num_queries;

extern unsigned int edns0_enabled;

#endif /* DNSCACHE_H */
