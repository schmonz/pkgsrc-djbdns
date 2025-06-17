#include "dns.h"

int mxname_data_diff(register const mxname_data *mxname1, register const mxname_data *mxname2)
{
  register int v1;
  register int v2;

  v1 = (int)mxname1->pref;
  v2 = (int)mxname2->pref;
  return v1 - v2;
}
