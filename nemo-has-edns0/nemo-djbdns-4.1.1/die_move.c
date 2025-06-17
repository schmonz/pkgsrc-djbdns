#include <nemo/strerr.h>

#include "die.h"

void die_move(const char *from, const char *to)
{
  strerr_die6sys(111, PROGRAM, _FATAL, "unable to move ", from, " to ", to);
}

