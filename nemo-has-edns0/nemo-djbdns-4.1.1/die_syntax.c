#include <nemo/strerr.h>
#include <nemo/fmt.h>

#include "die.h"

void die_syntax(unsigned int line, const char *why)
{
  char strnum[FMT_ULONG];
  strnum[fmt_ulong(strnum, line)] = '\0';
  strerr_die6x(111, PROGRAM, _FATAL, "syntax error, line: ", strnum, "; ", why);
}
