#include "dns.h"

static byte_t _d_localnet_ip6_arpa_str[] = "\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\001e\001f\003ip6\004arpa\0";
static const dns_domain _d_localnet_ip6_arpa = { _d_localnet_ip6_arpa_str, 74, sizeof(_d_localnet_ip6_arpa_str) };
const dns_domain *dns_d_localnet_ip6_arpa = &_d_localnet_ip6_arpa;
