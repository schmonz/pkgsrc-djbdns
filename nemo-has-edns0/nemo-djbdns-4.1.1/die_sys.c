#include <nemo/strerr.h>

#include "die.h"

void die_sys(const char *what)
{
  strerr_die3sys(111, PROGRAM, _FATAL, what);
}
