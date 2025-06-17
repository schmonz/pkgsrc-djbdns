#include "dns.h"

static byte_t _d_ip4_any_inaddr_arpa_str[] = "\0010\0010\0010\0010\007in-addr\004arpa\0";
static const dns_domain _d_ip4_any_inaddr_arpa = { _d_ip4_any_inaddr_arpa_str, 22, sizeof(_d_ip4_any_inaddr_arpa_str) };
const dns_domain *dns_d_any_inaddr_arpa = &_d_ip4_any_inaddr_arpa;
