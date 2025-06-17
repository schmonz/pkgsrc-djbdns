#include "dns.h"

int mxip6_data_diff(register const mxip6_data *mxip1, register const mxip6_data *mxip2)
{
  register int v1;
  register int v2;

  v1 = (int)mxip1->pref;
  v2 = (int)mxip2->pref;
  return v1 - v2;
}
