#include <nemo/strerr.h>

#include "die.h"

void die_dns_query(void)
{
  strerr_die3sys(111, PROGRAM, _FATAL, "dns query failed");
}
