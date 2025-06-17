#include <nemo/strerr.h>

#include "die.h"

void die_chroot(const char *dir)
{
  strerr_die4sys(111, PROGRAM, _FATAL, "unable to chroot to ", dir);
}
