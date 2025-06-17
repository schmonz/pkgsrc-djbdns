#ifndef NEMO_DEBUG
#define NEMO_DEBUG

#include "dns.h"

#ifdef DEBUG
void debug_putsa(const char *caption, const stralloc *sa);
void debug_putint(const char *caption, int i);
void debug_putuint(const char *caption, unsigned int i);
void debug_putip4(const char *caption, const ip4_address *ip);
void debug_putip6(const char *caption, const ip6_address *ip);
void debug_putdomain(const char *caption, const dns_domain *dn);
void debug_puttype(const char *caption, const dns_type *t);
void debug_putquery(const char *caption, const dns_domain *dn, const dns_type *t);
void debug_putnumquery(const char *caption, uint64_t qn, const dns_domain *dn, const dns_type *t);
#else
#define debug_putsa(caption, sa) /* */
#define debug_putint(caption, i) /* */
#define debug_putuint(caption, u) /* */
#define debug_putip4(caption, ip) /* */
#define debug_putip6(caption, ip) /* */
#define debug_putdomain(caption, dn) /* */
#define debug_puttype(caption, t) /* */
#define debug_putquery(caption, dn, t); /* */
#define debug_putnumquery(caption, qn, dn, t); /* */
#endif

#endif
