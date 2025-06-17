#include <nemo/strerr.h>

#include "die.h"

void die1(const char *what)
{
  strerr_die3x(111, PROGRAM, _FATAL, what);
}
