#ifndef CACHE_H
#define CACHE_H

#include <nemo/stdint.h>

#define MIN_TTL	60

typedef enum {
  CACHE_HIT = 0,
  CACHE_MISS,
  CACHE_EXPIRED,
  CACHE_NXDOMAIN,
  CACHE_SERVFAIL
} cache_t;

typedef enum {
  CACHE_SET_NEW = 0,
  CACHE_SET_OVERWRITE,
  CACHE_SET_NOTFOUND,
  CACHE_SET_NOTEXPIRED,
  CACHE_SET_HASHFLOOD,
  CACHE_SET_NOTALLOC,
  CACHE_SET_KEYLEN,
  CACHE_SET_DATALEN,
  CACHE_SET_EXHAUSTED
} cache_set_t;

extern uint64_t cache_motion;

#include "dns.h"
#include "dn_vector.h"
/*
  low level routines
*/
unsigned int	cache_init(unsigned int cachesize, uint32_t minttl);
cache_t		cache_get(const byte_t *key, unsigned int keylen, byte_t **data, unsigned int *datalen, uint32_t *ttl);
cache_set_t	cache_set(const byte_t *key, unsigned int keylen, unsigned int status, const byte_t *data, unsigned int datalen, uint32_t ttl);
cache_set_t	cache_expire(const byte_t *key, unsigned int keylen);

/*
  high level routines
*/
unsigned int	cache_make_key(const dns_type *type, const dns_domain *name, byte_t *key);

void		cache_generic(const dns_type *type, const dns_domain *name, const byte_t *data, unsigned int data_len, uint32_t ttl);
void		cache_mark(const dns_type *type, const dns_domain *name, unsigned int status, uint32_t ttl);

cache_t		cache_get_rr_cname(const dns_domain *name, dns_domain *cname);
cache_t		cache_get_rr_ns(const dns_domain *name, dn_vector *v);
cache_t		cache_get_rr_a(const dns_domain *name, ip4_vector *v);
cache_t		cache_get_rr_aaaa(const dns_domain *name, ip6_vector *v);

cache_t		cache_test_rr(const dns_type *type, const dns_domain *name);

void		cache_expire_rr(const dns_type *type, const dns_domain *name);

void		cache_set_info(const char *what, const dns_type *type, const dns_domain *name, unsigned int status, unsigned int datalen);

#endif
