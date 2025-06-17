#include <nemo/strerr.h>
#include <nemo/fmt.h>

#include "die.h"

void die_setuid(uid_t uid)
{
  char strnum[FMT_ULONG];
  strnum[fmt_ulong(strnum, (unsigned long)uid)] = '\0';
  strerr_die4sys(111, PROGRAM, _FATAL, "unable to set UID to ", strnum);
}
