#include "dns.h"

static byte_t _d_ip6_localhost_str[] = "\011localhost\0";
static const dns_domain _d_ip6_localhost = { _d_ip6_localhost_str, 11, sizeof(_d_ip6_localhost_str) };
const dns_domain *dns_d_ip6_localhost = &_d_ip6_localhost;
