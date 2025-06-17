#include "dns.h"

static byte_t _d_ip6_allhosts_str[] = "\015ipv6-allhosts\0";
static const dns_domain _d_ip6_allhosts = { _d_ip6_allhosts_str, 15, sizeof(_d_ip6_allhosts_str) };
const dns_domain *dns_d_ip6_allhosts = &_d_ip6_allhosts;
