#include "response.h"

unsigned int response_addtype(const dns_type *qt)
{
  byte_t data[2];

  dns_type_pack(qt, data);
  return response_addbytes(data, 2);
}
