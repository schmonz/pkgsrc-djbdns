#include <nemo/strerr.h>

#include "die.h"

void die_create2(const char *dir, const char *fn)
{
  strerr_die6sys(111, PROGRAM, _FATAL, "unable to create ", dir, "/", fn);
}
