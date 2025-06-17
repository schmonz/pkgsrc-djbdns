#ifndef NEMO_LOG_H
#define NEM_LOG_H

#include <nemo/stdint.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>

void	log_startup(unsigned int cachesize, uint32_t minttl, unsigned int flag_edns0);

void	log4_query(uint64_t query_number, const ip4_address *client, unsigned int port, const dns_id *id, const dns_domain *name, const dns_type *type, unsigned int flag_edns0, unsigned int udp_size);
void	log4_query_done(uint64_t query_number, unsigned int len, const ip4_address *client, unsigned int port, const dns_id *id, unsigned int loop_count, unsigned int rcode);
void	log4_drop_query(uint64_t query_number, unsigned int len, const ip4_address *client, unsigned int port, const dns_id *id, unsigned int loop_count);

void	log6_query(uint64_t query_number, const ip6_address *client, unsigned int port, const dns_id *id, const dns_domain *name, const dns_type *type, unsigned int flag_edns0, unsigned int udp_size);
void	log6_query_done(uint64_t query_number, unsigned int len, const ip6_address *client, unsigned int port, const dns_id *id, unsigned int loop_count, unsigned int rcode);
void	log6_drop_query(uint64_t query_number, unsigned int len, const ip6_address *client, unsigned int port, const dns_id *id, unsigned int loop_count);

void	log4_tcpopen(const ip4_address *client, unsigned int port);
void	log4_tcpclose(const ip4_address *client, unsigned int port);

void	log6_tcpopen(const ip6_address *client, unsigned int port);
void	log6_tcpclose(const ip6_address *client, unsigned int port);

void	log_tx_error(uint64_t query_number);
void	log_tx_piggyback(uint64_t query_number, const dns_domain *name, const dns_type *type, const dns_domain *control);

void	log4_tx(uint64_t query_number, const dns_domain *name, const dns_type *type, const dns_domain *control, const ip4_vector *servers);
void	log6_tx(uint64_t query_number, const dns_domain *name, const dns_type *type, const dns_domain *control, const ip6_vector *servers);

void	log4_rcode(unsigned int rcode, const ip4_address *server, const dns_domain *name, const dns_type *type, uint32_t ttl);
void	log4_nodata(const ip4_address *server, const dns_domain *name, const dns_type *type, uint32_t ttl);
void	log4_lame(const ip4_address *server, const dns_domain *control, const dns_domain *referral);
void	log4_ignore_referral(const ip4_address *server, const dns_domain *control, const dns_domain *referral);

void	log6_rcode(unsigned int rcode, const ip6_address *server, const dns_domain *name, const dns_type *type, uint32_t ttl);
void	log6_nodata(const ip6_address *server, const dns_domain *name, const dns_type *type, uint32_t ttl);
void	log6_lame(const ip6_address *server, const dns_domain *control, const dns_domain *referral);
void	log6_ignore_referral(const ip6_address *server, const dns_domain *control, const dns_domain *referral);

void	log4_rr(const ip4_address *server, const dns_domain *name, const dns_type *type, const byte_t *buf, unsigned int len, uint32_t ttl);
void	log4_rr_a(const ip4_address *server, const dns_domain *name, const ip4_address *ip, uint32_t ttl);
void	log4_rr_aaaa(const ip4_address *server, const dns_domain *name, const ip6_address *ip, uint32_t ttl);
void	log4_rr_ns(const ip4_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl);
void	log4_rr_cname(const ip4_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl);
void	log4_rr_ptr(const ip4_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl);
void	log4_rr_mx(const ip4_address *server, const dns_domain *name, const dns_domain *mx, const byte_t pref[2], uint32_t ttl);
void	log4_rr_soa(const ip4_address *server, const dns_domain *name, const dns_domain *n1, const dns_domain *n2, const byte_t misc[20], uint32_t ttl);

void	log6_rr(const ip6_address *server, const dns_domain *name, const dns_type *type, const byte_t *buf, unsigned int len, uint32_t ttl);
void	log6_rr_a(const ip6_address *server, const dns_domain *name, const ip4_address *ip, uint32_t ttl);
void	log6_rr_aaaa(const ip6_address *server, const dns_domain *name, const ip6_address *ip, uint32_t ttl);
void	log6_rr_ns(const ip6_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl);
void	log6_rr_cname(const ip6_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl);
void	log6_rr_ptr(const ip6_address *server, const dns_domain *name, const dns_domain *data, uint32_t ttl);
void	log6_rr_mx(const ip6_address *server, const dns_domain *name, const dns_domain *mx, const byte_t pref[2], uint32_t ttl);
void	log6_rr_soa(const ip6_address *server, const dns_domain *name, const dns_domain *n1, const dns_domain *n2, const byte_t misc[20], uint32_t ttl);

void	log_stats(void);

void	log_glueless_a(const dns_domain *name, const dns_domain *control);
void	log_glueless_aaaa(const dns_domain *name, const dns_domain *control);
void	log_local_fail(const dns_domain *name, const dns_type *type, const char *reason);
void	log_remote_fail(const dns_domain *name, const dns_type *type);
void	log_ns_loop(const dns_domain *name, const dns_domain *control);
void	log_ns_cname(const dns_domain *name, const dns_domain *control);
void	log_ns_fail(const dns_domain *name, const dns_domain *control);

void	log_cacheset(const char *what, const char *suffix, const dns_domain *name, const dns_type *type, unsigned int data_len);

void	log_info(const char *comment);
void	log_info_count(const char *comment, unsigned int count);
void	log_info_name(const dns_domain *name, const char *comment);
void	log_info_sys(const char *comment);

void	log4_rejected_source_ip(const ip4_address *ip);
void	log6_rejected_source_ip(const ip6_address *ip);
void	log4_rejected_packet(const ip4_address *ip, unsigned int port);
void	log6_rejected_packet(const ip6_address *ip, unsigned int port);
void	log_rejected_source_port(unsigned int port);

void	log4_ip_ttl_type_name(const char *prefix, const ip4_address *server, uint32_t ttl, const dns_type *type, const dns_domain *name);
void	log6_ip_ttl_type_name(const char *prefix, const ip6_address *server, uint32_t ttl, const dns_type *type, const dns_domain *name);

void	log_char(char c);
void	log_hex(byte_t c);
void	log_number(uint64_t l);
void	log_prefix(const char *s);
void	log_string(const char *s);
void	log_line(void);
void	log_space(void);
void	log_colon(void);
void	log_ip4(const ip4_address *i);
void	log_ip6(const ip6_address *i);
void	log_ip6_bracket(const ip6_address *ip);
void	log_id(const dns_id *id);
void	log_type(const dns_type *type);
void	log_domain(const dns_domain *q);
void	log_rcode(unsigned int rcode);

#endif
