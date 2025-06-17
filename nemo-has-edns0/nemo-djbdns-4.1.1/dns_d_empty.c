#include "dns.h"

static byte_t _d_empty_str[] = "\0";
static const dns_domain _d_empty = { _d_empty_str, 1, sizeof(_d_empty_str) };
const dns_domain *dns_d_empty = &_d_empty;
