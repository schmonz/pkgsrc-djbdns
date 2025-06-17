#include <nemo/strerr.h>
#include <nemo/fmt.h>

#include "die.h"

void die_setgid(gid_t gid)
{
  char strnum[FMT_ULONG];
  strnum[fmt_ulong(strnum, (unsigned long)gid)] = '\0';
  strerr_die4sys(111, PROGRAM, _FATAL, "unable to set GID to ", strnum);
}
