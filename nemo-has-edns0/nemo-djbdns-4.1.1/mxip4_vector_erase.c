#include "dns.h"

unsigned int mxip4_vector_erase(register mxip4_vector *vector)
{
  if (!mxip4_vector_ready(vector, 1)) return 0;
  vector->len = 0;
  return 1;
}
