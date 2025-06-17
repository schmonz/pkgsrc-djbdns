#ifndef IOQUERY_HAVEPACKET_H
#define IOQUERY_HAVEPACKET_H

extern ip4_vector ignore_ip4_list;
extern ip6_vector ignore_ip6_list;

extern dns_domain owner_name;
extern dns_domain referral;

extern unsigned int *records;
extern unsigned int rr_count;

uint32_t ioquery_ttl_get(byte_t *buf);

void ioquery_save_start(void);
void ioquery_save_data(const byte_t *buf, unsigned int len);
void ioquery_save_finish(const dns_type *type, const dns_domain *d, uint32_t ttl);

unsigned int ioquery_scan_records(const byte_t *buf, unsigned int len, unsigned int start, unsigned int query_type,
					unsigned int num_answers, unsigned int num_authority, unsigned int num_additional,
					unsigned int *flag_found, unsigned int *flag_soa, unsigned int *flag_referral,
					uint32_t *soa_ttl, unsigned int *pos_authority);
void ioquery_sort_records(const byte_t *buf, unsigned int len, unsigned int num_total);

unsigned int ignore_ip4(const ip4_address *ip);
unsigned int ignore_ip6(const ip6_address *ip);

unsigned int ioquery_opt_count(void);

#endif /* IOQUERY_HAVEPACKET_H */
