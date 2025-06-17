#include <nemo/strerr.h>

#include "die.h"

void die_usage(void)
{
  strerr_die4x(100, "usage: ", PROGRAM, " ", USAGE);
}
