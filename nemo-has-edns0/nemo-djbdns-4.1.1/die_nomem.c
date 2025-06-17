#include <nemo/strerr.h>

#include "die.h"

void die_nomem(void)
{
  strerr_die3x(111, PROGRAM, _FATAL, "out of memory");
}
