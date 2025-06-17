#include <nemo/strerr.h>

#include "die.h"

void die_dns_query1(const char *what)
{
  strerr_die4sys(111, PROGRAM, _FATAL, what, " dns query failed");
}
