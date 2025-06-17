#include "response.h"

unsigned int response_addip6(const ip6_address *ip)
{
  byte_t buf[16];

  ip6_pack(ip, buf);
  return response_addbytes(buf, 16);
}
