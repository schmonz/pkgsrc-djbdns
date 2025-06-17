#include <nemo/strerr.h>

#include "die.h"

void die_internal(void)
{
  strerr_die3sys(111, PROGRAM, _FATAL, "internal error");
}
