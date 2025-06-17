#include "dns.h"

static byte_t _d_ip6_allnodes_str[] = "\015ipv6-allnodes\0";
static const dns_domain _d_ip6_allnodes = { _d_ip6_allnodes_str, 15, sizeof(_d_ip6_allnodes_str) };
const dns_domain *dns_d_ip6_allnodes = &_d_ip6_allnodes;
