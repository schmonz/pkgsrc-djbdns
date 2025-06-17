#include "dns.h"
#include "die.h"
#include "respond.h"

void initialize(void)
{
  char seed[128];
  dns_random_init(seed);
}
