#ifndef NEMO_DNS_H
#define NEMO_DNS_H

#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/stralloc.h>
#include <nemo/sa_vector.h>
#include <nemo/tai.h>
#include <nemo/taia.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>
#include <nemo/iopause.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_UDP_SIZE_DEFAULT	512
#define DNS_UDP_SIZE_MAX	1410

#define DNS_SOA_TTL_DEFAULT		86400
#define DNS_SOA_REFRESH_TIME_DEFAULT	16384
#define DNS_SOA_RETRY_TIME_DEFAULT	2048

/* RFC 1912 -> 1209600 - 2419200 (2 - 4 weeks) */
#define DNS_SOA_EXPIRE_TIME_DEFAULT	1209600

/* RFC 2308 s5 -> 3600 - 86400 (1 hour - 1 day) */
#define DNS_SOA_MINIMUM_TIME_DEFAULT	3600

typedef enum {  /* RFC 1035 */
  DNS_RCODE_NOERROR = 0,
  DNS_RCODE_FORMERR = 1,
  DNS_RCODE_SERVFAIL = 2,
  DNS_RCODE_NXDOMAIN = 3,
  DNS_RCODE_NOTIMP = 4,
  DNS_RCODE_REFUSED = 5,
  DNS_RCODE_BADVERS = 16  /* rfc6891 */
} dns_rcode_t;

#define	DNS_HEADER_SIZE				12
#define	DNS_HEADER_QUERYID_OFFSET		0
#define	DNS_PACKET_FLAGS_OFFSET			2
#define	DNS_HEADER_QUERY_COUNT_OFFSET		4
#define	DNS_HEADER_ANSWER_COUNT_OFFSET		6
#define	DNS_HEADER_AUTHORITY_COUNT_OFFSET	8
#define	DNS_HEADER_ADDITIONAL_COUNT_OFFSET	10

#define DNS_QUESTION_HEADER_SIZE	4
#define DNS_QUESTION_TYPE_OFFSET	0
#define DNS_QUESTION_CLASS_OFFSET	2

#define DNS_RR_HEADER_SIZE		10
#define DNS_RR_TYPE_OFFSET		0
#define DNS_RR_CLASS_OFFSET		2
#define DNS_RR_TTL_OFFSET		4
#define DNS_RR_DATA_LENGTH_OFFSET	8

typedef struct {
  uint16_t d;
} dns_type;

#define DNS_TYPE {0}

typedef struct {
  uint16_t d;
} dns_class;

#define DNS_CLASS {0}

typedef struct {
  uint16_t d;
} dns_id;

#define DNS_ID {0}

struct dns4_transmit {
  byte_t *query;	/* 0, or dynamically allocated */
  unsigned int querylen;
  byte_t *packet;	/* 0, or dynamically allocated */
  unsigned int packetlen;
  int s;		/* -1, or an open file descriptor */
  int tcpstate;
  unsigned int udploop;
  unsigned int curserver;
  struct taia deadline;
  unsigned int pos;
  ip4_vector *servers;
  ip4_address localip;
  ip4_address curserverip;
  dns_type qtype;
};

#define DNS4_TRANSMIT {0,0,0,0,-1,0,0,0,TAIA,0,0,IP4_ADDRESS,IP4_ADDRESS,DNS_TYPE}

struct dns6_transmit {
  byte_t *query;	/* 0, or dynamically allocated */
  unsigned int querylen;
  byte_t *packet;	/* 0, or dynamically allocated */
  unsigned int packetlen;
  int s;		/* -1, or an open file descriptor */
  int tcpstate;
  unsigned int udploop;
  unsigned int curserver;
  struct taia deadline;
  unsigned int pos;
  ip6_vector *servers;
  ip6_address localip;
  ip6_address curserverip;
  dns_type qtype;
};

#define DNS6_TRANSMIT {0,0,0,0,-1,0,0,0,TAIA,0,0,IP6_ADDRESS,IP6_ADDRESS,DNS_TYPE}

typedef struct {
  byte_t *data;
  unsigned int len;
  unsigned int a;
} dns_domain;

#define DNS_DOMAIN {0,0,0}

typedef struct {
  stralloc sa;
  unsigned int pref;
} mxname_data;

#define MXNAME_DATA {STRALLOC,0}

typedef struct {
  mxname_data *va;
  unsigned int len;
  unsigned int a;
} mxname_vector;

#define MXNAME_VECTOR {0,0,0}

typedef struct {
  ip4_address ip;
  unsigned int pref;
} mxip4_data;

typedef struct {
  mxip4_data *va;
  unsigned int len;
  unsigned int a;
} mxip4_vector;

#define MXIP4_VECTOR {0,0,0}

typedef struct {
  ip6_address ip;
  unsigned int pref;
} mxip6_data;

typedef struct {
  mxip6_data *va;
  unsigned int len;
  unsigned int a;
} mxip6_vector;

#define MXIP6_VECTOR {0,0,0}

typedef struct {
  unsigned int pref;
  unsigned int ipmode;
  union {
    ip4_address ip4;
    ip6_address ip6;
  } ip;
} mxip_data;

#define MXIP_DATA { 0,6,IP6_ADDRESS }

typedef struct {
  mxip_data *va;
  unsigned int len;
  unsigned int a;
} mxip_vector;

#define MXIP_VECTOR { 0,0,0 }

typedef struct {
  stralloc mname;
  stralloc rname;
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minimum;
} soa_data;

#define SOA_DATA { STRALLOC,STRALLOC,0,0,0,0,0 }

typedef struct {
  soa_data *va;
  unsigned int len;
  unsigned int a;
} soa_vector;

#define SOA_VECTOR { 0,0,0 }

#define DNS_T_NIL	0
#define DNS_T_A		1
#define DNS_T_NS	2
#define DNS_T_CNAME	5
#define DNS_T_SOA	6
#define DNS_T_PTR	12
#define DNS_T_HINFO	13
#define DNS_T_MX	15
#define DNS_T_TXT	16
#define DNS_T_RP	17
#define DNS_T_SIG	24
#define DNS_T_KEY	25
#define DNS_T_AAAA	28
#define DNS_T_LOC	29
#define DNS_T_SRV	33
#define DNS_T_NAPTR	35
#define DNS_T_OPT	41
#define DNS_T_DS	43
#define DNS_T_RRSIG	46
#define DNS_T_NSEC	47
#define DNS_T_DNSKEY	48
#define DNS_T_SPF	99
#define DNS_T_IXFR	251
#define DNS_T_AXFR	252
#define DNS_T_ANY	255
#define DNS_T_CAA	257

extern const dns_type *dns_t_nil;
extern const dns_type *dns_t_a;
extern const dns_type *dns_t_ns;
extern const dns_type *dns_t_cname;
extern const dns_type *dns_t_soa;
extern const dns_type *dns_t_ptr;
extern const dns_type *dns_t_hinfo;
extern const dns_type *dns_t_mx;
extern const dns_type *dns_t_txt;
extern const dns_type *dns_t_rp;
extern const dns_type *dns_t_sig;
extern const dns_type *dns_t_key;
extern const dns_type *dns_t_aaaa;
extern const dns_type *dns_t_loc;
extern const dns_type *dns_t_srv;
extern const dns_type *dns_t_naptr;
extern const dns_type *dns_t_opt;
extern const dns_type *dns_t_ds;
extern const dns_type *dns_t_rrsig;
extern const dns_type *dns_t_nsec;
extern const dns_type *dns_t_dnskey;
extern const dns_type *dns_t_spf;
extern const dns_type *dns_t_ixfr;
extern const dns_type *dns_t_axfr;
extern const dns_type *dns_t_any;
extern const dns_type *dns_t_caa;

#define DNS_C_IN        1
#define DNS_C_ANY       255

extern const dns_class *dns_c_in;
extern const dns_class *dns_c_any;

extern const dns_domain *dns_d_empty;

extern const dns_domain *dns_d_ip4_localhost;

extern const dns_domain *dns_d_any_inaddr_arpa;
extern const dns_domain *dns_d_localhost_inaddr_arpa;
extern const dns_domain *dns_d_base_inaddr_arpa;

extern const dns_domain *dns_d_ip6_localhost;
extern const dns_domain *dns_d_ip6_localnet;
extern const dns_domain *dns_d_ip6_mcastprefix;
extern const dns_domain *dns_d_ip6_allnodes;
extern const dns_domain *dns_d_ip6_allrouters;
extern const dns_domain *dns_d_ip6_allhosts;

extern const dns_domain *dns_d_any_ip6_arpa;
extern const dns_domain *dns_d_localhost_ip6_arpa;
extern const dns_domain *dns_d_localnet_ip6_arpa;
extern const dns_domain *dns_d_mcastprefix_ip6_arpa;
extern const dns_domain *dns_d_allnodes_ip6_arpa;
extern const dns_domain *dns_d_allrouters_ip6_arpa;
extern const dns_domain *dns_d_allhosts_ip6_arpa;
extern const dns_domain *dns_d_base_ip6_arpa;

extern struct dns4_transmit dns4_resolve_tx;
extern struct dns6_transmit dns6_resolve_tx;

extern struct dns4_transmit dns4_notify_tx;
extern struct dns6_transmit dns6_notify_tx;

#define	dns_type_diffd dns_type_diffb
#define	dns_type_equald dns_type_equalb

void		dns_type_copy(dns_type *out, const dns_type *in);
void		dns_type_unpack(dns_type *out, const void *in);
void		dns_type_pack(const dns_type *in, void *out);
unsigned int	dns_type_equal(const dns_type *t1, const dns_type *t2);
unsigned int	dns_type_equalb(const dns_type *t, const void *data);
unsigned int	dns_type_diff(const dns_type *t1, const dns_type *t2);
unsigned int	dns_type_diffb(const dns_type *t, const void *data);
unsigned int	dns_type_parse(dns_type *t, const char *s);
const char	*dns_type_str(unsigned int i);
void		dns_type_set(dns_type *out, unsigned int in);
unsigned int	dns_type_get(const dns_type *t);
void		dns_type_zero(dns_type *t);

#define	dns_class_equald dns_class_equalb
#define dns_class_diffd dns_class_diffb

void		dns_class_copy(dns_class *out, const dns_class *in);
void		dns_class_unpack(dns_class *out, const void *in);
void		dns_class_pack(const dns_class *in, void *out);
unsigned int	dns_class_equal(const dns_class *c1, const dns_class *c2);
unsigned int	dns_class_equalb(const dns_class *c, const void *data);
unsigned int	dns_class_diff(const dns_class *c1, const dns_class *c2);
unsigned int	dns_class_diffb(const dns_class *c, const void *data);
void		dns_class_zero(dns_class *c);

void		dns_id_unpack(dns_id *out, const void *in);
void		dns_id_pack(const dns_id *in, void *out);
/*
void		dns_id_copy(dns_id *out, const dns_id *in);
unsigned int	dns_id_equal(const dns_id *id1, const dns_id *id2);
unsigned int	dns_id_equalb(const dns_id *id, const char *data);
unsigned int	dns_id_diff(const dns_id *id1, const dns_id *id2);
unsigned int	dns_id_diffb(const dns_id *id, const char *data);
void		dns_id_zero(dns_id *id);
*/
/*
  domain name routines
*/
static inline void dns_domain_init(register dns_domain *dn)
{
  dn->data = 0;
  dn->len = dn->a = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int dns_domain_realloc(register dns_domain *dn, register unsigned int n);
unsigned int dns_domain_alloc(register dns_domain *dn, register unsigned int n);

static inline unsigned int dns_domain_ready(register dns_domain *dn, register unsigned int n)
{
  if (dn->data) {
    if (n <= dn->a) return 1;
    return dns_domain_realloc(dn, n);
  }
  return dns_domain_alloc(dn, n);
}

static inline unsigned int dns_domain_readyplus(register dns_domain *dn, register unsigned int n)
{
  if (dn->data) {
    n += dn->len;
    if (n <= dn->a) return 1;
    return dns_domain_realloc(dn, n);
  }
  return dns_domain_alloc(dn, n);
}

void		dns_domain_free(dns_domain *d);
unsigned int	dns_domain_erase(dns_domain *d);
unsigned int	dns_domain_active(const dns_domain *d);
unsigned int	dns_domain_copy(dns_domain *out, const dns_domain *in);
unsigned int	dns_domain_copyb(dns_domain *out, const void *buf, unsigned int len);
unsigned int	dns_domain_cat(dns_domain *out, const dns_domain *in);
unsigned int	dns_domain_catb(dns_domain *out, const void *buf, unsigned int len);
unsigned int	dns_domain_unpack(dns_domain *out, const void *data);
void		dns_domain_pack(const dns_domain *in, void *out);
void		dns_domain_lower(dns_domain *d);
unsigned int	dns_domain_drop1label(dns_domain *d);  /* return 1 if label dropped */
unsigned int	dns_domain_labellength(const dns_domain *dn);
unsigned int	dns_domain_labelcount(const dns_domain *dn);
unsigned int	dns_domain_labelparse(const dns_domain *dn, sa_vector *out);  /* out is reverse sorted */
int		dns_domain_diff(const dns_domain *dn1, const dns_domain *dn2);
unsigned int	dns_domain_equal(const dns_domain *dn1, const dns_domain *dn2);
unsigned int	dns_domain_suffix(const dns_domain *big, const dns_domain *little);
unsigned int	dns_domain_suffixpos(const dns_domain *big, const dns_domain *little);
unsigned int	dns_domain_fromdot(dns_domain *out, const void *buf, unsigned int len);
unsigned int	dns_domain_todot_cat(const dns_domain *dn, stralloc *out);
unsigned int	dns_domain_ok(const dns_domain *dn);
/*
  return (total) length, safely
*/
static inline unsigned int dns_domain_length(register const dns_domain *dn)
{
  if (dn->data) return dn->len;
  return 1;
}
unsigned int	dns_domain_lengthplus(const dns_domain *dn, unsigned int i);

unsigned int	dns_packet_getname(const byte_t *buf, unsigned int len, unsigned int pos, dns_domain *d);
unsigned int	dns_packet_skipname(const byte_t *buf, unsigned int len, unsigned int pos);
unsigned int	dns_packet_copy(const byte_t *buf, unsigned int len, unsigned int pos, byte_t *out, unsigned int outlen);

unsigned int	dns_qualify_do_rule(stralloc *work, const stralloc *rule);

void	dns_sortip4(ip4_vector *v);
void	dns_sortip6(ip6_vector *v);

void	dns4_transmit_init(struct dns4_transmit *d);
int	dns4_transmit_start(struct dns4_transmit *d, ip4_vector *servers, unsigned int flag_recursive, const dns_domain *q, const dns_type *qtype, const ip4_address *localip);
int	dns4_transmit_start_edns0(struct dns4_transmit *d, ip4_vector *servers, unsigned int flag_recursive, const dns_domain *q, const dns_type *qtype, const ip4_address *localip);
int	dns4_transmit_start_notify(struct dns4_transmit *dt, ip4_vector *servers, const dns_domain *qname, const ip4_address *localip);
void	dns4_transmit_free(struct dns4_transmit *d);
void	dns4_transmit_io(struct dns4_transmit *d, iopause_fd *x, struct taia *deadline);
int	dns4_transmit_get(struct dns4_transmit *d, iopause_fd *x, const struct taia *when);

void	dns6_transmit_init(struct dns6_transmit *d);
int	dns6_transmit_start(struct dns6_transmit *d, ip6_vector *servers, unsigned int flag_recursive, const dns_domain *q, const dns_type *qtype, const ip6_address *localip);
int	dns6_transmit_start_edns0(struct dns6_transmit *d, ip6_vector *servers, unsigned int flag_recursive, const dns_domain *q, const dns_type *qtype, const ip6_address *localip);
int	dns6_transmit_start_notify(struct dns6_transmit *dt, ip6_vector *servers, const dns_domain *qname, const ip6_address *localip);
void	dns6_transmit_free(struct dns6_transmit *d);
void	dns6_transmit_io(struct dns6_transmit *d, iopause_fd *x, struct taia *deadline);
int	dns6_transmit_get(struct dns6_transmit *d, iopause_fd *x, const struct taia *when);

int	dns_resolve_conf_ip4(ip4_vector *servers);
int	dns_resolve_conf_ip6(ip6_vector *servers);

int	dns4_resolve(const dns_domain *q, const dns_type *qtype);
int	dns6_resolve(const dns_domain *q, const dns_type *qtype);

int	dns4_notify(const ip4_address *local_ip, const stralloc *domain, const ip4_address *server_ip);
int	dns6_notify(const ip6_address *local_ip, const stralloc *domain, const ip6_address *server_ip);

int	dns_ip4_packet(ip4_vector *out, const byte_t *buf, unsigned int len);
int	dns_ip6_packet(ip6_vector *out, const byte_t *buf, unsigned int len);
int	dns_name_packet(sa_vector *out, const byte_t *buf, unsigned int len);
int	dns_ns_packet(sa_vector *out, const byte_t *buf, unsigned int len);
int	dns_txt_packet(sa_vector *out, const byte_t *buf, unsigned int len, const dns_type *type);
int	dns_mx_packet(mxname_vector *out, const byte_t *buf, unsigned int len);
int	dns_soa_packet(soa_vector *out, const byte_t *buf, unsigned int len);

int	dns4_ip4(ip4_vector *out, const stralloc *fqdn);
int	dns4_ip4_qualify_rules(ip4_vector *out, stralloc *fqdn, const stralloc *in, const sa_vector *rules);
int	dns4_ip4_qualify(ip4_vector *out, stralloc *fqdn, const stralloc *in);

int	dns6_ip4(ip4_vector *out, const stralloc *fqdn);
int	dns6_ip4_qualify_rules(ip4_vector *out, stralloc *fqdn, const stralloc *in, const sa_vector *rules);
int	dns6_ip4_qualify(ip4_vector *out, stralloc *fqdn, const stralloc *in);

int	dns4_ip6(ip6_vector *out, const stralloc *fqdn);
int	dns4_ip6_qualify_rules(ip6_vector *out, stralloc *fqdn, const stralloc *in, const sa_vector *rules);
int	dns4_ip6_qualify(ip6_vector *out, stralloc *fqdn, const stralloc *in);

int	dns6_ip6(ip6_vector *out, const stralloc *fqdn);
int	dns6_ip6_qualify_rules(ip6_vector *out, stralloc *fqdn, const stralloc *in, const sa_vector *rules);
int	dns6_ip6_qualify(ip6_vector *out, stralloc *fqdn, const stralloc *in);

int	dns_name4_domain(dns_domain *out, const ip4_address *ip);
int	dns_name6_domain(dns_domain *out, const ip6_address *ip);

int	dns4_name4(sa_vector *out, const ip4_address *ip);
int	dns4_name6(sa_vector *out, const ip6_address *ip);

int	dns6_name4(sa_vector *out, const ip4_address *ip);
int	dns6_name6(sa_vector *out, const ip6_address *ip);

int	dns4_txt(sa_vector *out, const stralloc *fqdn);
int	dns6_txt(sa_vector *out, const stralloc *fqdn);

int	dns4_spf(sa_vector *out, const stralloc *fqdn);
int	dns6_spf(sa_vector *out, const stralloc *fqdn);

int	dns4_mx(mxname_vector *out, const stralloc *fqdn);
int	dns6_mx(mxname_vector *out, const stralloc *fqdn);

int	dns4_mxip4(mxip4_vector *out, const stralloc *fqdn);
int	dns6_mxip4(mxip4_vector *out, const stralloc *fqdn);

int	dns4_mxip6(mxip6_vector *out, const stralloc *fqdn);
int	dns6_mxip6(mxip6_vector *out, const stralloc *fqdn);

int	dns4_soa(soa_vector *out, const stralloc *fqdn);
int	dns6_soa(soa_vector *out, const stralloc *fqdn);

int	dns4_ns(sa_vector *out, const stralloc *fqdn);
int	dns6_ns(sa_vector *out, const stralloc *fqdn);

int	mxip4_data_diff(const mxip4_data *a, const mxip4_data *b);  /* required by mxip4_vector_sort() */
int	mxip6_data_diff(const mxip6_data *a, const mxip6_data *b);  /* required by mxip6_vector_sort() */
int	mxip_data_diff46(const mxip_data *a, const mxip_data *b);  /* required by mxip_vector_sort46() */
int	mxip_data_diff64(const mxip_data *a, const mxip_data *b);  /* required by mxip_vector_sort64() */
int	mxname_data_diff(const mxname_data *a, const mxname_data *b);  /* required by mxname_vector_sort() */

static inline void mxname_vector_init(register mxname_vector *v)
{
  v->va = 0;
  v->len = v->a = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int mxname_vector_realloc(mxname_vector *v, unsigned int n);
unsigned int mxname_vector_alloc(mxname_vector *v, unsigned int n);

static inline unsigned int mxname_vector_ready(register mxname_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return mxname_vector_realloc(v, n);
  }
  return mxname_vector_alloc(v, n);
}

static inline unsigned int mxname_vector_readyplus(register mxname_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return mxname_vector_realloc(v, n);
  }
  return mxname_vector_alloc(v, n);
}

unsigned int	mxname_vector_erase(mxname_vector *v);
unsigned int	mxname_vector_append(mxname_vector *v, const stralloc *name, unsigned int pref);
unsigned int	mxname_vector_remove(mxname_vector *v, unsigned int i);
void		mxname_vector_sort(mxname_vector *v);
void		mxname_vector_swap(mxname_vector *v, unsigned int pos, unsigned int pos2);

static inline void mxip4_vector_init(register mxip4_vector *v)
{
  v->va = 0;
  v->len = v->a = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int mxip4_vector_realloc(mxip4_vector *v, unsigned int n);
unsigned int mxip4_vector_alloc(mxip4_vector *v, unsigned int n);

static inline unsigned int mxip4_vector_ready(register mxip4_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return mxip4_vector_realloc(v, n);
  }
  return mxip4_vector_alloc(v, n);
}

static inline unsigned int mxip4_vector_readyplus(register mxip4_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return mxip4_vector_realloc(v, n);
  }
  return mxip4_vector_alloc(v, n);
}

unsigned int	mxip4_vector_append(mxip4_vector *v, const ip4_address *ip, unsigned int pref);
unsigned int	mxip4_vector_erase(mxip4_vector *v);
void		mxip4_vector_sort(mxip4_vector *v);
void		mxip4_vector_swap(mxip4_vector *v, unsigned int pos, unsigned int pos2);

static inline void mxip6_vector_init(register mxip6_vector *v)
{
  v->va = 0;
  v->len = v->a = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int mxip6_vector_realloc(mxip6_vector *v, unsigned int n);
unsigned int mxip6_vector_alloc(mxip6_vector *v, unsigned int n);

static inline unsigned int mxip6_vector_ready(register mxip6_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return mxip6_vector_realloc(v, n);
  }
  return mxip6_vector_alloc(v, n);
}

static inline unsigned int mxip6_vector_readyplus(register mxip6_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return mxip6_vector_realloc(v, n);
  }
  return mxip6_vector_alloc(v, n);
}

unsigned int	mxip6_vector_append(mxip6_vector *v, const ip6_address *ip, unsigned int pref);
unsigned int	mxip6_vector_erase(mxip6_vector *v);
void		mxip6_vector_sort(mxip6_vector *v);
void		mxip6_vector_swap(mxip6_vector *v, unsigned int pos, unsigned int pos2);

static inline void mxip_vector_init(register mxip_vector *v)
{
  v->va = 0;
  v->len = v->a = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int mxip_vector_realloc(mxip_vector *v, unsigned int n);
unsigned int mxip_vector_alloc(mxip_vector *v, unsigned int n);

static inline unsigned int mxip_vector_ready(register mxip_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return mxip_vector_realloc(v, n);
  }
  return mxip_vector_alloc(v, n);
}

static inline unsigned int mxip_vector_readyplus(register mxip_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return mxip_vector_realloc(v, n);
  }
  return mxip_vector_alloc(v, n);
}

unsigned int	mxip_vector_append4(mxip_vector *v, const mxip4_data *d);
unsigned int	mxip_vector_append6(mxip_vector *v, const mxip6_data *d);
unsigned int	mxip_vector_cat4(mxip_vector *out, const mxip4_vector *in);
unsigned int	mxip_vector_cat6(mxip_vector *out, const mxip6_vector *in);
void		mxip_vector_sort46(mxip_vector *v);
void		mxip_vector_sort64(mxip_vector *v);
void		mxip_vector_swap(mxip_vector *v, unsigned int pos, unsigned int pos2);

static inline void soa_vector_init(register soa_vector *v)
{
  v->va = 0;
  v->len = v->a = 0;
}

/*  return: 1 = success, 0 = fail  */
unsigned int soa_vector_realloc(soa_vector *v, unsigned int n);
unsigned int soa_vector_alloc(soa_vector *v, unsigned int n);

static inline unsigned int soa_vector_ready(register soa_vector *v, register unsigned int n)
{
  if (v->va) {
    if (n <= v->a) return 1;
    return soa_vector_realloc(v, n);
  }
  return soa_vector_alloc(v, n);
}

static inline unsigned int soa_vector_readyplus(register soa_vector *v, register unsigned int n)
{
  if (v->va) {
    n += v->len;
    if (n <= v->a) return 1;
    return soa_vector_realloc(v, n);
  }
  return soa_vector_alloc(v, n);
}

unsigned int	soa_vector_erase(soa_vector *v);
unsigned int	soa_vector_append(soa_vector *v, const soa_data *data);
/*
  general/misc
*/
const char	*dns_rcode_str(unsigned int rcode);

unsigned int	byte_domain_length(const void *dn);

void		dns_random_init(const char data[128]);
unsigned int	dns_random(unsigned int n);

int		dns_resolve_conf_rewrite(sa_vector *rules);

unsigned int	dns_idna_encode(stralloc *out, const stralloc *in);

#ifdef __cplusplus
}
#endif

#endif
