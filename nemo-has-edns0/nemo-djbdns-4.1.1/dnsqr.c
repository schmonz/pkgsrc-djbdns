#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/scan.h>
#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/error.h>
#include <nemo/exit.h>
#include <nemo/iopause.h>
#include <nemo/sgetopt.h>

#include "dns.h"
#include "die.h"
#include "printpacket.h"

const char USAGE[] = "[ -46] type name";

static dns_type type;
static dns_domain qname = DNS_DOMAIN;

static stralloc out = STRALLOC;

static unsigned int flag_ipv6 = 0;

int main(int argc, char **argv)
{
  char seed[128];
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

  if (!*argv) die_usage1("missing type");
  if (!dns_type_parse(&type, *argv)) die_usage();

  if (!*++argv) die_usage1("missing name");
  if (!dns_domain_fromdot(&qname, *argv, str_len(*argv))) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_parse("name", *argv);
    die_internal();
  }
  dns_domain_lower(&qname);

  if (!stralloc_erase(&out)) die_nomem();
  if (!stralloc_catulong0(&out, dns_type_get(&type), 0)) die_nomem();
  if (!stralloc_append(&out, " ")) die_nomem();
  if (!dns_domain_todot_cat(&qname, &out)) die_nomem();
  if (!stralloc_append(&out, ":")) die_nomem();
  if (!stralloc_append(&out, "\n")) die_nomem();

  if (flag_ipv6) {
    if (dns6_resolve(&qname, &type) < 0) {
      djbio_puts(djbiofd_out, error_str(errno));
      djbio_puteol(djbiofd_out);
    }
    else {
      if (dns6_resolve_tx.packetlen < 4) die_parse("name", *argv);
      dns6_resolve_tx.packet[2] &= (byte_t)(~1);
      dns6_resolve_tx.packet[3] &= (byte_t)(~128);
      if (!printpacket_cat(dns6_resolve_tx.packet, dns6_resolve_tx.packetlen, &out)) die_parse("name", *argv);
      djbio_putsa(djbiofd_out, &out);
    }
  }
  else {
    if (dns4_resolve(&qname, &type) < 0) {
      djbio_puts(djbiofd_out, error_str(errno));
      djbio_puteol(djbiofd_out);
    }
    else {
      if (dns4_resolve_tx.packetlen < 4) die_parse("name", *argv);
      dns4_resolve_tx.packet[2] &= (byte_t)(~1);
      dns4_resolve_tx.packet[3] &= (byte_t)(~128);
      if (!printpacket_cat(dns4_resolve_tx.packet, dns4_resolve_tx.packetlen, &out)) die_parse("name", *argv);
      djbio_putsa(djbiofd_out, &out);
    }
  }
  djbio_flush(djbiofd_out);
  _exit(0);
}
