#include "dns.h"

static byte_t _d_base_inaddr_arpa_str[] = "\007in-addr\004arpa\0";
static const dns_domain _d_base_inaddr_arpa = { _d_base_inaddr_arpa_str, 14, sizeof(_d_base_inaddr_arpa_str) };
const dns_domain *dns_d_base_inaddr_arpa = &_d_base_inaddr_arpa;
