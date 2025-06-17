#include <nemo/byte.h>

#include "dns.h"

int dns6_ip6_qualify_rules(ip6_vector *out, stralloc *fqdn, const stralloc *in, const sa_vector *rules)
{
  unsigned int i;
  unsigned int j;
  unsigned int plus;
  unsigned int fqdnlen;

  if (!stralloc_copy(fqdn, in)) return -1;

  for (i = 0; i < rules->len; ++i) {
    if (!dns_qualify_do_rule(fqdn, &rules->va[i])) return -1;
  }

  fqdnlen = fqdn->len;
  plus = byte_chr(fqdn->s, fqdnlen, '+');
  if (plus >= fqdnlen) {
    return dns6_ip6(out, fqdn);
  }

  i = plus + 1;
  for (;;) {
    j = byte_chr(fqdn->s + i, fqdnlen - i, '+');
    byte_copy(fqdn->s + plus, j, fqdn->s + i);
    fqdn->len = plus + j;
    if (dns6_ip6(out, fqdn) < 0) return -1;
    if (out->len) return 0;
    i += j;
    if (i >= fqdnlen) return 0;
    ++i;
  }
}

int dns6_ip6_qualify(ip6_vector *out, stralloc *fqdn, const stralloc *in)
{
  static sa_vector rules = SA_VECTOR;
  if (dns_resolve_conf_rewrite(&rules) < 0) return -1;
  return dns6_ip6_qualify_rules(out, fqdn, in, &rules);
}
