#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/exit.h>
#include <nemo/fmt.h>
#include <nemo/scan.h>

#include "dns.h"

static ip4_address ip;
static unsigned int ipfixed = 0;
static unsigned long loops = 10000;
static byte_t tab[256];

static char strnum[FMT_ULONG];

int main(int argc, char **argv)
{
  char seed[128];
  unsigned long u;
  unsigned int i;
  unsigned int j;
  byte_t c;

  dns_random_init(seed);

  for (i = 0; i < 256; ++i) {
    tab[i] = (byte_t)i;
  }
  for (j = 256; j > 0; --j) {
    i = dns_random(j);
    c = tab[j - 1];
    tab[j - 1] = tab[i];
    tab[i] = c;
  }

  if (argc) {
    ++argv;
  }
  if (*argv) {
    scan_ulong(*argv++, &loops);
  }
  if (*argv) {
    scan_ulong(*argv++, &u);
    ip.d[0] = (byte_t)u;
    ipfixed = 1;
  }
  if (*argv) {
    scan_ulong(*argv++, &u);
    ip.d[1] = (byte_t)u;
    ipfixed = 2;
  }
  if (*argv) {
    scan_ulong(*argv++, &u);
    ip.d[2] = (byte_t)u;
    ipfixed = 3;
  }
  if (*argv) {
    scan_ulong(*argv++, &u);
    ip.d[3] = (byte_t)u;
    ipfixed = 4;
  }

  if (ipfixed >= 1) {
    if (loops > 16777216) {
      loops = 16777216;
    }
  }
  if (ipfixed >= 2) {
    if (loops > 65536) {
      loops = 65536;
    }
  }
  if (ipfixed >= 3) {
    if (loops > 256) {
      loops = 256;
    }
  }
  if (ipfixed >= 4) {
    if (loops > 1) {
      loops = 1;
    }
  }

  while (loops) {
    --loops;
    u = loops;
    for (i = ipfixed; i < 4; ++i) {
      ip.d[i] = u & 255;
      u >>= 8;
    }
    if (ipfixed == 3) {
      c = ip.d[3];
      ip.d[3] = tab[c];
    }
    else if (ipfixed < 3) {
      c = 0;
      for (j = 0; j < 100; ++j) {
        for (i = ipfixed; i < 4; ++i) {
          c ^= (byte_t) ip.d[i];
          c = tab[c];
          ip.d[i] = c;
        }
      }
    }

    u = ip.d[0];
    djbio_put(djbiofd_out, strnum, fmt_ulong(strnum, u));
    djbio_puts(djbiofd_out, ".");
    u = ip.d[1];
    djbio_put(djbiofd_out, strnum, fmt_ulong(strnum, u));
    djbio_puts(djbiofd_out, ".");
    u = ip.d[2];
    djbio_put(djbiofd_out, strnum, fmt_ulong(strnum, u));
    djbio_puts(djbiofd_out, ".");
    u = ip.d[3];
    djbio_put(djbiofd_out, strnum, fmt_ulong(strnum, u));
    djbio_puts(djbiofd_out, "\n");
  }

  djbio_flush(djbiofd_out);
  _exit(0);
}
