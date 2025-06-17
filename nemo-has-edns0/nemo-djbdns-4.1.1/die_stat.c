#include <nemo/strerr.h>

#include "die.h"

void die_stat(const char *fn)
{
  strerr_die4sys(111, PROGRAM, _FATAL, "unable to stat ", fn);
}
