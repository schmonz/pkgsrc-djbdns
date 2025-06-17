#include <nemo/strerr.h>

#include "die.h"

void die_env(const char *name)
{
  strerr_die5x(100, PROGRAM, _FATAL, "$", name, " not set");
}
