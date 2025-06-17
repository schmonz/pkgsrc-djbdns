#include <nemo/strerr.h>

#include "die.h"

void die_not_found(const char *what, const char *value)
{
  strerr_die6sys(111, PROGRAM, _FATAL, "unable to find ", what, " for ", value);
}
