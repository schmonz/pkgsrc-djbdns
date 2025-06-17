#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/exit.h>
#include <nemo/sgetopt.h>

#include "dns.h"
#include "die.h"

const char USAGE[] = "[ -46 ] fqdn ...";

static stralloc fqdn = STRALLOC;
static sa_vector out = SA_VECTOR;
static unsigned int flag_ipv6 = 0;

int main(int argc, char **argv)
{
  char seed[128];
  unsigned int i;
  int opt;

  PROGRAM = *argv;
  dns_random_init(seed);

  while ((opt = getopt(argc, argv, "46")) != opteof) {
    switch (opt) {
      case '4':
        flag_ipv6 = 0;
        break;
      case '6':
        flag_ipv6 = 1;
        break;
      default:
        die_usage();
        break;
    }
  }
  argv += optind;

  while (*argv) {
    if (!stralloc_copys(&fqdn, *argv)) die_nomem();
    stralloc_lower(&fqdn);
    if (flag_ipv6) {
      if (dns6_txt(&out, &fqdn) < 0) die_rr_query("TXT", *argv);
    }
    else {
      if (dns4_txt(&out, &fqdn) < 0) die_rr_query("TXT", *argv);
    }
    for (i = 0; i < out.len; i++) {
      djbio_putsa(djbiofd_out, &out.va[i]);
      djbio_puteol(djbiofd_out);
    }
    djbio_flush(djbiofd_out);
    ++argv;
  }

  _exit(0);
}
