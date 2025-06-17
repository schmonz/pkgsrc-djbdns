#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/env.h>
#include <nemo/scan.h>
#include <nemo/prot.h>
#include <nemo/unix.h>

#include "droproot.h"
#include "die.h"

void droproot(void)
{
  const char *x;
  unsigned long id;

  x = env_get("ROOT");
  if (!x) die_env("ROOT");
  if (chdir(x) < 0) die_chdir(x);
  if (chroot(".") < 0) die_chroot(x);

  x = env_get("GID");
  if (!x) die_env("GID");
  scan_ulong(x, &id);
  if (prot_gid((gid_t)id) < 0) die_setgid((gid_t)id);

  x = env_get("UID");
  if (!x) die_env("UID");
  scan_ulong(x, &id);
  if (prot_uid((uid_t)id) < 0) die_setuid((uid_t)id);
}
