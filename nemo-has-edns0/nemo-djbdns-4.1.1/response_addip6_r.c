#include "response.h"

unsigned int response_addip6_r(const ip6_address *ip)
{
  ip6_address ip6r;

  ip6_copy(&ip6r, ip);
  ip6_reverse(&ip6r);
  return response_addip6(&ip6r);
}
