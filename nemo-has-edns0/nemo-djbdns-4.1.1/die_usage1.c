#include <nemo/strerr.h>

#include "die.h"

void die_usage1(const char *message)
{
  strerr_die6x(100, "usage: ", PROGRAM, " ", USAGE, " : ", message);
}
