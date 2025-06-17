#include <nemo/strerr.h>

#include "die.h"

void die_rr_query(const char *rrtype, const char *query)
{
  strerr_die6sys(111, PROGRAM, _FATAL, "unable to find ", rrtype, " records for ", query);
}
