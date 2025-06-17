/*
  primarily to test dns_domain_fromdot()
*/

#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/error.h>
#include <nemo/strerr.h>
#include <nemo/exit.h>
#include <nemo/str.h>
#include <nemo/macro_unused.h>

#include "dns.h"

const char FATAL[] = "test_domain_name_decode: fatal: ";  /* global */

static dns_domain t = DNS_DOMAIN;

static void check(const char *d, unsigned int expect_ok)
{
  unsigned int r;

  r = dns_domain_fromdot(&t, d, str_len(d));

  if (expect_ok && r) return;
  if (!expect_ok && !r) return;

  if (expect_ok) {  /* r == 0 */
    if (errno == error_nomem) strerr_die3x(1, FATAL, "nomem: ", d);
    if (errno == error_proto) strerr_die3x(1, FATAL, "proto: ", d);
    strerr_die3sys(1, FATAL, "system error: ", d);
  }
/*
  r == 1
*/
  strerr_die3sys(1, FATAL, "false positive: ", d);
}

int main(int argc __UNUSED__, char **argv __UNUSED__)
{
  check("", 1);
  check(".", 1);
  check("\\056", 1);  /* "." */
  check("www.example.com", 1);
  check("www.example.com.", 1);

  check("..", 0);
  check(".www.example.com", 0);
  check("www..example.com", 0);
  check("www..example.com.", 0);

  check("very.longlonglonglonglonglonglonglonglonglonglonglonglonglonglongexample.com", 0);

  _exit(0);
}
