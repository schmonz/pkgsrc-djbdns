#include "dns.h"

static byte_t _d_ip6_localnet_str[] = "\015ipv6-localnet\0";
static const dns_domain _d_ip6_localnet = { _d_ip6_localnet_str, 15, sizeof(_d_ip6_localnet_str) };
const dns_domain *dns_d_ip6_localnet = &_d_ip6_localnet;
