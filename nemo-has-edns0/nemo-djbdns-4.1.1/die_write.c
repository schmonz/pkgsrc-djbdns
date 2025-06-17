#include <nemo/strerr.h>

#include "die.h"

void die_write(const char *fn)
{
  strerr_die4sys(111, PROGRAM, _FATAL, "unable to write to ", fn);
}

