#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/exit.h>
#include <nemo/sgetopt.h>
#include <nemo/error.h>

#include "dns.h"
#include "die.h"

const char USAGE[] = "[ -46 ] fqdn ...";

static stralloc fqdn = STRALLOC;
static stralloc buffer = STRALLOC;
static dns_domain qname = DNS_DOMAIN;
static mxname_vector out = MXNAME_VECTOR;
static unsigned int flag_ipv6 = 0;

int main(int argc, char **argv)
{
  char seed[128];
  unsigned int i;
  mxname_data *mx;
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
      if (dns6_mx(&out, &fqdn) < 0) die_rr_query("MX", *argv);
    }
    else {
      if (dns4_mx(&out, &fqdn) < 0) die_rr_query("MX", *argv);
    }
    mxname_vector_sort(&out);
    if (!out.len) {
      if (!stralloc_copyb(&buffer, "0 ", 2)) die_nomem();
      if (!dns_domain_fromdot(&qname, fqdn.s, fqdn.len)) {
	if (errno == error_nomem) die_nomem();
	if (errno == error_proto) die_parse("fqdn", *argv);
	die_internal();
      }
      if (!dns_domain_todot_cat(&qname, &buffer)) die_nomem();
      djbio_putsa(djbiofd_out, &buffer);
      djbio_puteol(djbiofd_out);
    }
    else {
      for (i = 0; i < out.len; i++) {
        mx = &out.va[i];
        if (!stralloc_erase(&buffer)) die_nomem();
        if (!stralloc_catulong(&buffer, mx->pref)) die_nomem();
        if (!stralloc_append(&buffer, " ")) die_nomem();
        if (!stralloc_cat(&buffer, &mx->sa)) die_nomem();
        djbio_putsa(djbiofd_out, &buffer);
        djbio_puteol(djbiofd_out);
      }
    }
    djbio_flush(djbiofd_out);
    ++argv;
  }

  _exit(0);
}
