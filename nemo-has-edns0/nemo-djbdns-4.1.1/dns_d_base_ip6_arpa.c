#include "dns.h"

static byte_t _d_base_ip6_arpa_str[] = "\003ip6\004arpa\0";
static const dns_domain _d_base_ip6_arpa = { _d_base_ip6_arpa_str, 10, sizeof(_d_base_ip6_arpa_str) };
const dns_domain *dns_d_base_ip6_arpa = &_d_base_ip6_arpa;
