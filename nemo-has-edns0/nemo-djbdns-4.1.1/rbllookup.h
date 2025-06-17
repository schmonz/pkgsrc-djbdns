#ifndef RBLLOOKUP_H
#define RBLLOOKUP_H

#define MAX_DATA 255
#define TTL_DNS 2048
#define TTL_CDB 5

extern const char FATAL[];

extern dns_domain base;

unsigned int rbllookup_ip_fmt(char *data);
int rbllookup_cdb_find(void *key, unsigned int len);

unsigned int rbllookup_respond(const dns_domain *qname, unsigned int flag_a, unsigned int flag_txt);

#endif /* RBLLOOKUP_H */
