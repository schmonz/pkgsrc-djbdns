#include <nemo/strerr.h>

#include "die.h"

void die_bogus_query(const char *what)
{
  strerr_die4x(111, PROGRAM, _FATAL, "bogus query: ", what);
}
