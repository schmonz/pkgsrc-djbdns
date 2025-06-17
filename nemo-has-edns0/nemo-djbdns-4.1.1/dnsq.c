#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/fmt.h>
#include <nemo/scan.h>
#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/error.h>
#include <nemo/exit.h>
#include <nemo/sgetopt.h>
#include <nemo/iopause.h>

#include "dns.h"
#include "die.h"
#include "printpacket.h"

const char USAGE[] = "[ -46 ] type name server";  /* global */

static void outb(const char *buf, unsigned int len)
{
  djbio_put(djbiofd_out, buf, len);
}

static void outs(const char *out)
{
  djbio_puts(djbiofd_out, out);
}

static void outsa(const stralloc *out)
{
  djbio_putsa(djbiofd_out, out);
}

static void outeol(void)
{
  djbio_puteol(djbiofd_out);
  djbio_flush(djbiofd_out);
}

static void outip4(ip4_address *ip)
{
  char fmtstr[IP4_FMT];
  outb(fmtstr, ip4_fmt(ip, fmtstr));
}

static void outip4list(const ip4_vector *list)
{
  unsigned int i;
  for (i = 0; i < list->len; i++) {
    outip4(&list->va[i]);
    outeol();
  }
}

static void outip6(ip6_address *ip)
{
  char fmtstr[IP6_FMT];
  outb(fmtstr, ip6_fmt(ip, fmtstr));
}

static void outip6list(const ip6_vector *list)
{
  unsigned int i;
  for (i = 0; i < list->len; i++) {
    outip6(&list->va[i]);
    outeol();
  }
}

static struct dns4_transmit tx4 = DNS4_TRANSMIT;
static struct dns6_transmit tx6 = DNS6_TRANSMIT;

static int resolve4(const dns_domain *qname, const dns_type *qtype, ip4_vector *servers)
{
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (dns4_transmit_start(&tx4, servers, 0, qname, qtype, null_ip4) < 0) return -1;
  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);
    dns4_transmit_io(&tx4, x, &deadline);
    iopause(x, 1, &deadline, &stamp);
    r = dns4_transmit_get(&tx4, x, &stamp);
    if (r < 0) return -1;
    if (r == 1) break;
  }
  return 0;
}

static int resolve6(const dns_domain *qname, const dns_type *qtype, ip6_vector *servers)
{
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (dns6_transmit_start(&tx6, servers, 0, qname, qtype, null_ip6) < 0) return -1;
  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);
    dns6_transmit_io(&tx6, x, &deadline);
    iopause(x, 1, &deadline, &stamp);
    r = dns6_transmit_get(&tx6, x, &stamp);
    if (r < 0) return -1;
    if (r) break;
  }
  return 0;
}

static ip4_vector servers4 = IP4_VECTOR;
static ip6_vector servers6 = IP6_VECTOR;

static dns_type type;
static dns_domain qname = DNS_DOMAIN;

static stralloc fqdn = STRALLOC;
static stralloc server = STRALLOC;

static stralloc buf = STRALLOC;

static unsigned int flag_ipv6 = 0;

int main(int argc, char **argv)
{
  char seed[128];
  char fmtstr[FMT_ULONG];
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
    if (errno == error_proto) die_parse("fqdn", *argv);
    die_internal();
  }
  dns_domain_lower(&qname);

  if (!*++argv) die_usage1("missing server");
  if (!stralloc_copys(&server, *argv)) die_nomem();
  stralloc_lower(&server);

  if (flag_ipv6) {
    if (dns6_ip6_qualify(&servers6, &fqdn, &server) < 0) die_parse("fqdn", *argv);
    outip6list(&servers6);
  }
  else {
    if (dns4_ip4_qualify(&servers4, &fqdn, &server) < 0) die_parse("fqdn", *argv);
    outip4list(&servers4);
  }

  outb(fmtstr, fmt_ulong(fmtstr, dns_type_get(&type)));
  outb(" ", 1);

  if (!stralloc_erase(&buf)) die_nomem();
  if (!dns_domain_todot_cat(&qname, &buf)) die_nomem();
  outsa(&buf);
  outb(":", 1);
  outeol();

  if (!stralloc_erase(&buf)) die_nomem();
  if (flag_ipv6) {
    if (resolve6(&qname, &type, &servers6) < 0) {
      outs(error_str(errno));
      outeol();
    }
    else {
      if (!printpacket_cat(tx6.packet, tx6.packetlen, &buf)) die_parse("fqdn", *argv);
      outsa(&buf);
    }
  }
  else {
    if (resolve4(&qname, &type, &servers4) < 0) {
      outs(error_str(errno));
      outeol();
    }
    else {
      if (!printpacket_cat(tx4.packet, tx4.packetlen, &buf)) die_parse("fqdn", *argv);
      outsa(&buf);
    }
  }
  djbio_flush(djbiofd_out);

  _exit(0);
}
