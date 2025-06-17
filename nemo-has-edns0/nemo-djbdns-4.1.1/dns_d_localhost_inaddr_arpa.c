#include "dns.h"

static byte_t _d_ip4_localhost_inaddr_arpa_str[] = "\0011\0010\0010\003127\007in-addr\004arpa\0";
static const dns_domain _d_ip4_localhost_inaddr_arpa = { _d_ip4_localhost_inaddr_arpa_str, 24, sizeof(_d_ip4_localhost_inaddr_arpa_str) };
const dns_domain *dns_d_localhost_inaddr_arpa = &_d_ip4_localhost_inaddr_arpa;
