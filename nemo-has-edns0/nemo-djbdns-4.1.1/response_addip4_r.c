#include "response.h"

unsigned int response_addip4_r(const ip4_address *ip)
{
  ip4_address ip4r;

  ip4_copy(&ip4r, ip);
  ip4_reverse(&ip4r);
  return response_addip4(&ip4r);
}
