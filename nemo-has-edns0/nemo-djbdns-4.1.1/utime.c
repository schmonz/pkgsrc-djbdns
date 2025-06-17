#include <sys/types.h>
#include <sys/time.h>
#include <utime.h>

#include <nemo/stdint.h>
#include <nemo/uint32.h>
#include <nemo/scan.h>
#include <nemo/exit.h>

extern int utime(const char *file, const struct utimbuf *timep);

static char *fn;

static char *ustr;
static unsigned long u;
static struct utimbuf ut;

int main(int argc, char **argv)
{
  if (argc != 3) _exit(100);

  fn = argv[1];
  ustr = argv[2];
  scan_ulong(ustr, &u);

  ut.actime = ut.modtime = (time_t)u;
  if (utime(fn, &ut) < 0) _exit(111);
  _exit(0);
}
