#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/exit.h>
#include <nemo/sgetopt.h>

#include "dns.h"
#include "die.h"

const char USAGE[] = "[ -46 ] fqdn ...";

static stralloc in = STRALLOC;
static stralloc fqdn = STRALLOC;
static ip4_vector out = IP4_VECTOR;
static char str[IP4_FMT];
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
    if (!stralloc_copys(&in, *argv)) die_nomem();
    stralloc_lower(&fqdn);
    if (flag_ipv6) {
      if (dns6_ip4_qualify(&out, &fqdn, &in) < 0) die_not_found("IP address", *argv);
    }
    else {
      if (dns4_ip4_qualify(&out, &fqdn, &in) < 0) die_not_found("IP address", *argv);
    }

    djbio_putsa(djbiofd_out, &fqdn);
    djbio_put(djbiofd_out, " ", 1);
    for (i = 0; i < out.len; i++) {
      djbio_put(djbiofd_out, str, ip4_fmt(&out.va[i], str));
      djbio_put(djbiofd_out, " ", 1);
    }
    djbio_puteol(djbiofd_out);
    djbio_flush(djbiofd_out);

    ++argv;
  }

  djbio_flush(djbiofd_out);
  _exit(0);
}
