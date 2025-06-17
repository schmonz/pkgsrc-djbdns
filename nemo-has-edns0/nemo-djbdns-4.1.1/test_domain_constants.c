/*
  primarily to test defined dns_domain constants for usability
*/

#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/error.h>
#include <nemo/strerr.h>
#include <nemo/exit.h>
#include <nemo/macro_unused.h>

#include "dns.h"

const char FATAL[] = "test_domain_constants: fatal: ";  /* global */

static stralloc	sa = STRALLOC;
static dns_domain t = DNS_DOMAIN;

static void die_nomem(const char *func, const char *what)
{
  strerr_die5x(1, FATAL, "nomem: ", func, ": ", what);
}
static void die_proto(const char *func, const char *what)
{
  strerr_die5x(1, FATAL, "proto: ", func, ": ", what);
}
static void die_other(const char *func, const char *what)
{
  strerr_die5sys(1, FATAL, "other: ", func, ": ", what);
}

static void check(const char *prefix, const dns_domain *d)
{
  register unsigned int r;

  if (!stralloc_erase(&sa)) die_nomem("stralloc_erase(sa)", prefix);
  if (!dns_domain_todot_cat(d, &sa)) {
    if (errno == error_nomem) die_nomem("dns_domain_todot_cat(d)", prefix);
    if (errno == error_proto) die_proto("dns_domain_todot_cat(d)", prefix);
    die_other("dns_domain_todot_cat(d)", prefix);
  }
  if (!dns_domain_fromdot(&t, sa.s, sa.len)) {
    if (errno == error_nomem) die_nomem("dns_domain_fromdot(t)", prefix);
    if (errno == error_proto) die_proto("dns_domain_fromdot(t)", prefix);
    die_other("dns_domain_fromdot(t)", prefix);
  }

  r = dns_domain_equal(d, &t);
  if (!r) {
    djbio_puts(djbiofd_out, "test ");
    djbio_puts(djbiofd_out, prefix);
    djbio_puts(djbiofd_out, ": ");
    djbio_puts(djbiofd_out, "fail");
    djbio_puteol(djbiofd_out);

    djbio_puts(djbiofd_out, ">");
    if (!stralloc_cats(&sa, " ")) die_nomem("stralloc_cats(sa)", prefix);
    if (!stralloc_catuint(&sa, d->len)) die_nomem("stralloc_catuint(sa, d->len)", prefix);
    djbio_putsa(djbiofd_out, &sa);
    djbio_puteol(djbiofd_out);

    if (!stralloc_erase(&sa)) die_nomem("stralloc_erase(sa)", prefix);
    if (!dns_domain_todot_cat(&t, &sa)) {
      if (errno == error_nomem) die_nomem("dns_domain_todot_cat(t)", prefix);
      if (errno == error_proto) die_proto("dns_domain_todot_cat(t)", prefix);
      die_other("dns_domain_todot_cat(t)", prefix);
    }
    djbio_puts(djbiofd_out, "*");
    if (!stralloc_cats(&sa, " ")) die_nomem("stralloc_cats(sa)", prefix);
    if (!stralloc_catuint(&sa, t.len)) die_nomem("stralloc_catuint(sa, t.len)", prefix);
    djbio_putsa(djbiofd_out, &sa);
    djbio_puteol(djbiofd_out);
  }

  djbio_flush(djbiofd_out);
  if (!r) _exit(1);
}

int main(int argc __UNUSED__, char **argv __UNUSED__)
{
  check("empty", dns_d_empty);

  check("ip4 localhost", dns_d_ip4_localhost);
  check("localhost inaddr arpa", dns_d_localhost_inaddr_arpa);
  check("base inaddr arpa", dns_d_base_inaddr_arpa);

  check("ip6 localhost", dns_d_ip6_localhost);
  check("ip6 localnet", dns_d_ip6_localnet);
  check("ip6 mcast prefix", dns_d_ip6_mcastprefix);
  check("ip6 all nodes", dns_d_ip6_allnodes);
  check("ip6 all routers", dns_d_ip6_allrouters);
  check("ip6 all hosts", dns_d_ip6_allhosts);

  check("localhost ip6 arpa", dns_d_localhost_ip6_arpa);
  check("localnet ip6 arpa", dns_d_localnet_ip6_arpa);
  check("mcast prefix ip6 arpa", dns_d_mcastprefix_ip6_arpa);
  check("all nodes ip6 arpa", dns_d_allnodes_ip6_arpa);
  check("all routers ip6 arpa", dns_d_allrouters_ip6_arpa);
  check("all hosts ip6 arpa", dns_d_allhosts_ip6_arpa);

  check("base ip6 arpa", dns_d_base_ip6_arpa);
  _exit(0);
}
