#include <nemo/strerr.h>

#include "die.h"

void die_servers(void)
{
  strerr_die3sys(111, PROGRAM, _FATAL, "unable to read from servers");
}
