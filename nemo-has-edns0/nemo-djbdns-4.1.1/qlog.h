#ifndef NEMO_QLOG_H
#define NEMO_QLOG_H

#include <nemo/ip4.h>
#include <nemo/ip6.h>
#include <nemo/uint16.h>

void	qlog_put(const void *buf, unsigned int len);

/* following routines flush output */
void	qlog_starting(const char *program);
void	qlog_putline(const char *s);
void	qlog(uint16_t port, const dns_id *id, const dns_domain *qname, const dns_type *qtype, const char *result);
void	qlog4(const ip4_address *ip, uint16_t port, const dns_id *id, const dns_domain *qname, const dns_type *qtype, const char *result);
void	qlog6(const ip6_address *ip, uint16_t port, const dns_id *id, const dns_domain *qname, const dns_type *qtype, const char *result);

#endif
