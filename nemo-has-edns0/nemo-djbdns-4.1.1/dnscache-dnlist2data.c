#include <nemo/exit.h>
#include <nemo/cdb_make.h>
#include <nemo/open.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/getln.h>
#include <nemo/unix.h>
#include <nemo/error.h>

#include "dns.h"
#include "die.h"
#include "whitespace.h"

const char USAGE[] = "ip [...]";  /* global */

static unsigned int line_num = 0;

static stralloc fqdn = STRALLOC;

static void die_syntax_error(const char *why)
{
  die_syntax(line_num, why);
}

int main(int argc, char **argv)
{
  register int i;
  unsigned int match;

  PROGRAM = *argv;
  if (argc < 2) die_usage();

  djbio_puts(djbiofd_out, "#\n# WARNING: This file was auto-generated.\n#\n");

  match = 1;
  while (match) {
    line_num++;
    if (getln(djbiofd_in, &fqdn, &match, '\n') < 0) {
      if (errno == error_intr) continue;
      die_syntax_error("input error");
    }
    stralloc_trim(&fqdn, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!fqdn.len) continue;
    if (fqdn.s[0] == '#') continue;
    stralloc_lower(&fqdn);
    djbio_put(djbiofd_out, "+", 1);
    djbio_putsa(djbiofd_out, &fqdn);
    for (i = 1; i < argc; i++) {
      djbio_put(djbiofd_out, ":", 1);
      djbio_puts(djbiofd_out, argv[i]);
    }
    djbio_puteol(djbiofd_out);
  }
  djbio_flush(djbiofd_out);

  _exit(0);
}
