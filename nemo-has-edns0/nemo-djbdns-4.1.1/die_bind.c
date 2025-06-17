#include <nemo/strerr.h>

#include "die.h"

void die_bind(const char *what)
{
  strerr_die5sys(111, PROGRAM, _FATAL, "unable to bind ", what, " socket");
}
