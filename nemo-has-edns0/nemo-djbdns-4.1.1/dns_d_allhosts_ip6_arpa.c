#include "dns.h"

static byte_t _d_allhosts_ip6_arpa_str[] = "\0011\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0012\0010\001f\001f\003ip6\004arpa\0";
static const dns_domain _d_allhosts_ip6_arpa = { _d_allhosts_ip6_arpa_str, 74, sizeof(_d_allhosts_ip6_arpa_str) };
const dns_domain *dns_d_allhosts_ip6_arpa = &_d_allhosts_ip6_arpa;
