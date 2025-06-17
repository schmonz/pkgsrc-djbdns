#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/exit.h>
#include <nemo/sgetopt.h>

#include "dns.h"
#include "die.h"

const char USAGE[] = "[ -46 ] ip ...";

static sa_vector out = SA_VECTOR;
static unsigned int flag_ipv6 = 0;

int main(int argc, char **argv)
{
  char seed[128];
  ip4_address ip4;
  ip6_address ip6;
  unsigned int i;
  char *x;
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
    x = *argv;
    i = ip6_scan(&ip6, x);
    if (!x[i]) {
      if (flag_ipv6) {
	if (dns6_name6(&out, &ip6) < 0) die_not_found("host", x);
      }
      else {
	if (dns4_name6(&out, &ip6) < 0) die_not_found("host", x);
      }
    }
    else {
      i = ip4_scan(&ip4, x);
      if (!x[i]) {
        if (flag_ipv6) {
	  if (dns6_name4(&out, &ip4) < 0) die_not_found("host", x);
	}
        else {
	  if (dns4_name4(&out, &ip4) < 0) die_not_found("host", x);
	}
      }
      else {
        die_parse("IP address", x);
      }
    }
    for (i = 0; i < out.len; i++) {
      if (i) {
        djbio_put(djbiofd_out, " ", 1);
      }
      djbio_putsa(djbiofd_out, &out.va[i]);
    }
    djbio_puteol(djbiofd_out);
    djbio_flush(djbiofd_out);
    ++argv;
  }

  _exit(0);
}
