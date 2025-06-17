#include <nemo/strerr.h>

#include "die.h"

void die_chmod(const char *name)
{
  strerr_die4sys(111, PROGRAM, _FATAL, "unable to set mode of ", name);
}
