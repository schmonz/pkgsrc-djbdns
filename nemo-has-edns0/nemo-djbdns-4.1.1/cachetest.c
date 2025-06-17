#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/exit.h>
#include <nemo/str.h>
#include <nemo/strerr.h>

#include "cache.h"

const char FATAL[] = "cachetest: fatal: ";  /* global */

int main(int argc, char **argv)
{
  unsigned int status;
  unsigned int i;
  unsigned int u;
  byte_t *x;
  byte_t *y;
  uint32_t ttl;

  if (!cache_init(2000, 30)) _exit(111);

  if (argc) ++argv;

  while ((x = (byte_t*)*argv++)) {
    i = str_chr(x, ':');
    if (x[i]) {
      cache_set(x, i, CACHE_HIT, x + i + 1, str_len(x) - i - 1, 86400);
    }
    else {
      status = cache_get(x, i, &y, &u, &ttl);
      if (status == CACHE_HIT) {
        djbio_put(djbiofd_out, y, u);
      }
      djbio_puteol(djbiofd_out);
    }
  }

  djbio_flush(djbiofd_out);
  _exit(0);
}
