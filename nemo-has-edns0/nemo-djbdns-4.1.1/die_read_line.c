#include <nemo/strerr.h>
#include <nemo/fmt.h>

#include "die.h"

void die_read_line(unsigned int n)
{
  char strnum[FMT_ULONG];
  strnum[fmt_ulong(strnum, n)] = '\0';
  strerr_die4sys(111, PROGRAM, _FATAL, "unable to read from line: ", strnum);
}

