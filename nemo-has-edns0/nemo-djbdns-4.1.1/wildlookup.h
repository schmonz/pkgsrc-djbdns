#ifndef WILDLOOKUP_H
#define WILDLOOKUP_H

#define MAX_DATA 259
#define TTL_DNS 2048
#define TTL_CDB 5

unsigned int wildlookup_doit(const dns_domain *qname, const dns_type *qtype);

#endif /* WILDLOOKUP_H */
