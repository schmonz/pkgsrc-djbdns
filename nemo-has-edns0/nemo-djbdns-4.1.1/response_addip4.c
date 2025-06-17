#include "response.h"

unsigned int response_addip4(const ip4_address *ip)
{
  byte_t buf[4];

  ip4_pack(ip, buf);
  return response_addbytes(buf, 4);
}
