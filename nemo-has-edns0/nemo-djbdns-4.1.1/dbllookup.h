#ifndef DBLLOOKUP_H
#define DBLLOOKUP_H

#define MAX_DATA 255
#define TTL_DNS 2048
#define TTL_CDB 5

extern const char FATAL[];

unsigned int dbllookup_doit(const dns_domain *qname, const dns_type *qtype);

#endif /* DBLLOOKUP_H */
