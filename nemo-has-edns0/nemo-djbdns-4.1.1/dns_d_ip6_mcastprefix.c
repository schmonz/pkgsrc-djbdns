#include "dns.h"

static byte_t _d_ip6_mcastprefix_str[] = "\020ipv6-mcastprefix\0";
static const dns_domain _d_ip6_mcastprefix = { _d_ip6_mcastprefix_str, 18, sizeof(_d_ip6_mcastprefix_str) };
const dns_domain *dns_d_ip6_mcastprefix = &_d_ip6_mcastprefix;
