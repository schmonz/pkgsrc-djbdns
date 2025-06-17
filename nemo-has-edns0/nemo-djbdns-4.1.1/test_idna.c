/*
  primarily to test dns_idna_*()
*/

#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/error.h>
#include <nemo/strerr.h>
#include <nemo/exit.h>
#include <nemo/str.h>
#include <nemo/macro_unused.h>

#include "dns.h"

const char FATAL[] = "test_punycode: fatal: ";  /* global */

static void test_encode(const char *in, const char *expected)
{
  static stralloc input = STRALLOC;
  static stralloc output = STRALLOC;

  if (!stralloc_copys(&input, in)) {
    if (errno == error_nomem) strerr_die3x(1, FATAL, "nomem: ", expected);
    if (errno == error_proto) strerr_die3x(1, FATAL, "proto: ", expected);
    strerr_die3sys(1, FATAL, "system error: ", expected);
  }
  if (!dns_idna_encode(&output, &input)) {
    if (errno == error_nomem) strerr_die3x(1, FATAL, "nomem: ", expected);
    if (errno == error_proto) strerr_die3x(1, FATAL, "proto: ", expected);
    strerr_die3sys(1, FATAL, "system error: ", expected);
  }

  if (stralloc_equals(&output, expected)) return;

  if (!stralloc_0(&output)) {
    if (errno == error_nomem) strerr_die3x(1, FATAL, "nomem: ", expected);
    if (errno == error_proto) strerr_die3x(1, FATAL, "proto: ", expected);
    strerr_die3sys(1, FATAL, "system error: ", expected);
  }

  strerr_die5x(1, FATAL, "expected: ", expected, ", actual: ", output.s);
}

int main(int argc __UNUSED__, char **argv __UNUSED__)
{
  test_encode("\317\200.cr.yp.to", "xn--1xa.cr.yp.to");
  test_encode("\317\200.\317\200.cr.yp.to", "xn--1xa.xn--1xa.cr.yp.to");
  test_encode("b\303\274cher.tld", "xn--bcher-kva.tld");
  test_encode("b\303\274cher.b\303\274cher.tld", "xn--bcher-kva.xn--bcher-kva.tld");

  _exit(0);
}
