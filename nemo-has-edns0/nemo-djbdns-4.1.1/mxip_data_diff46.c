#include "dns.h"

int mxip_data_diff46(register const mxip_data *mxip1, register const mxip_data *mxip2)
{
  register int r;
  register int v1;
  register int v2;

  v1 = (int)mxip1->pref;
  v2 = (int)mxip2->pref;
  r = v1 - v2;
  if (r) return r;
/*
  IPv4 before IPv6
*/
  v1 = (int)mxip1->ipmode;
  v2 = (int)mxip2->ipmode;
  return v1 - v2;
}
