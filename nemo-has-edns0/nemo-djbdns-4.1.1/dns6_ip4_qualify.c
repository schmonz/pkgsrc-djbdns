#include <nemo/byte.h>

#include "dns.h"

int dns6_ip4_qualify_rules(ip4_vector *out, stralloc *fqdn, const stralloc *in, const sa_vector *rules)
{
  unsigned int i;
  unsigned int j;
  unsigned int plus;
  unsigned int fqdn_len;

  if (!stralloc_copy(fqdn, in)) return -1;

  for (i = 0; i < rules->len; ++i) {
    if (!dns_qualify_do_rule(fqdn, &rules->va[i])) return -1;
  }

  fqdn_len = fqdn->len;
  plus = byte_chr(fqdn->s, fqdn_len, '+');
  if (plus >= fqdn_len) {
    return dns6_ip4(out, fqdn);
  }

  i = plus + 1;
  for (;;) {
    j = byte_chr(fqdn->s + i, fqdn_len - i, '+');
    byte_copy(fqdn->s + plus, j, fqdn->s + i);
    fqdn->len = plus + j;
    if (dns6_ip4(out, fqdn) < 0) return -1;
    if (out->len) return 0;
    i += j;
    if (i >= fqdn_len) return 0;
    ++i;
  }
}

int dns6_ip4_qualify(ip4_vector *out, stralloc *fqdn, const stralloc *in)
{
  static sa_vector rules = SA_VECTOR;
  if (dns_resolve_conf_rewrite(&rules) < 0) return -1;
  return dns6_ip4_qualify_rules(out, fqdn, in, &rules);
}
