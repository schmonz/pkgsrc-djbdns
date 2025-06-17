#include "response.h"

unsigned int response_addclass(const dns_class *qc)
{
  byte_t data[2];

  dns_class_pack(qc, data);
  return response_addbytes(data, 2);
}
