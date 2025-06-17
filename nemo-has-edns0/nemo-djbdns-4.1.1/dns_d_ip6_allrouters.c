#include "dns.h"

static byte_t _d_ip6_allrouters_str[] = "\017ipv6-allrouters\0";
static const dns_domain _d_ip6_allrouters = { _d_ip6_allrouters_str, 17, sizeof(_d_ip6_allrouters_str) };
const dns_domain *dns_d_ip6_allrouters = &_d_ip6_allrouters;
