#include "dns.h"

unsigned int mxip6_vector_erase(register mxip6_vector *vector)
{
  if (!mxip6_vector_ready(vector, 1)) return 0;
  vector->len = 0;
  return 1;
}
