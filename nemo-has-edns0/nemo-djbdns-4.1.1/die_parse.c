#include <nemo/strerr.h>

#include "die.h"

void die_parse(const char *name, const char *value)
{
  strerr_die6x(111, PROGRAM, _FATAL, "unable to parse ", name, ": ", value);
}
