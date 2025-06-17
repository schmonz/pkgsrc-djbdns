#include <nemo/strerr.h>

#include "die.h"

void die_create_device(const char *dir, const char *device)
{
  strerr_die6sys(111, PROGRAM, _FATAL, "unable to create device ", dir, "/", device);
}
