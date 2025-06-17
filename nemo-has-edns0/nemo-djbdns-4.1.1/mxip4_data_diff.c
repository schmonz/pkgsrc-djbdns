#include "dns.h"

int mxip4_data_diff(register const mxip4_data *mxip1, register const mxip4_data *mxip2)
{
  register int v1;
  register int v2;

  v1 = (int)mxip1->pref;
  v2 = (int)mxip2->pref;
  return v1 - v2;
}
