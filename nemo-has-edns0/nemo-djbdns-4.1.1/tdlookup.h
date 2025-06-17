#ifndef TDLOOKUP_H
#define TDLOOKUP_H

#define TTL_CDB 5
#define KEY_PREFIX_LEN 4
#define LOC_LEN 2

extern byte_t	client_loc[LOC_LEN];

unsigned int	tdlookup_loc_setup(void *key, unsigned int keylen);
unsigned int	tdlookup_doit(const dns_domain *qname, const dns_type *qtype, unsigned int udp_size, unsigned int flag_edns0);

#endif /* TDLOOKUP_H */
