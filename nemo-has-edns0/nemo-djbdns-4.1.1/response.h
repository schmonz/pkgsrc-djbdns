#ifndef NEMO_RESPONSE_H
#define NEMO_RESPONSE_H

#include <nemo/stdint.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>

#include "dns.h"

extern byte_t response[];
extern unsigned int response_len;

unsigned int	response_query(const dns_domain *q, const dns_type *qtype, const dns_class *qclass);
void		response_nxdomain(void);
void		response_servfail(void);
void		response_formerr(void);
void		response_notimp(void);
void		response_refused(void);
void		response_id(const dns_id *id);
void		response_tc(void);  /* truncate */

unsigned int	response_addbytes(const void *buf, unsigned int len);
unsigned int	response_addip4(const ip4_address *ip);
unsigned int	response_addip4_r(const ip4_address *ip);
unsigned int	response_addip6(const ip6_address *ip);
unsigned int	response_addip6_r(const ip6_address *ip);
unsigned int	response_addtype(const dns_type *qt);
unsigned int	response_addclass(const dns_class *qc);
unsigned int	response_addname(const dns_domain *dname);
unsigned int	response_adduint16(uint16_t u);
void		response_hidettl(void);

unsigned int	response_rr_start(const dns_domain *d, const dns_type *type, uint32_t ttl);
void		response_rr_finish(unsigned int);

unsigned int	response_opt_start(unsigned int udp_size, unsigned int rcode);
void		response_opt_finish(void);
unsigned int	response_opt_error(unsigned int rcode);

unsigned int	response_cname(const dns_domain *c, const dns_domain *d, uint32_t ttl);

void		response_send4(int fd, const ip4_address *ip, uint16_t port);
void		response_send6(int fd, const ip6_address *ip, uint16_t port);

#endif
