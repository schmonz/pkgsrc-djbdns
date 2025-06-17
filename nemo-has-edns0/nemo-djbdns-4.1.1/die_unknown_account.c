#include <nemo/strerr.h>

#include "die.h"

void die_unknown_account(const char *account)
{
  strerr_die4x(111, PROGRAM, _FATAL, "unknown account: ", account);
}
