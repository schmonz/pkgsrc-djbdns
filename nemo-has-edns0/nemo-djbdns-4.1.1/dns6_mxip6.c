#include <nemo/error.h>

#include "dns.h"

int dns6_mxip6(mxip6_vector *out, const stralloc *fqdn)
{
  static mxname_vector mxv = MXNAME_VECTOR;
  static ip6_vector ipv = IP6_VECTOR;
  mxname_data *cur;
  unsigned int i;
  unsigned int j;

  if (!mxip6_vector_erase(out)) return -1;
  if (dns6_mx(&mxv, fqdn) < 0) return -1;
  if (!mxv.len) {  /* fallback */
    if (dns6_ip6(&ipv, fqdn) < 0) return -1;
    for (j = 0; j < ipv.len; j++) {
      mxip6_vector_append(out, &ipv.va[j], 0);
    }
  }
  for (i = 0; i < mxv.len; i++) {
    cur = &mxv.va[i];
    if (dns6_ip6(&ipv, &cur->sa) < 0) {
      if (errno == error_nomem) return -1;
      continue;
    }
    for (j = 0; j < ipv.len; j++) {
      mxip6_vector_append(out, &ipv.va[j], cur->pref);
    }
  }
  return 0;
}
