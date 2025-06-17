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

const char USAGE[] = "fqdn";  /* global */

static unsigned int line_num = 0;

static stralloc line = STRALLOC;

static void die_syntax_error(const char *why)
{
  die_syntax(line_num, why);
}

int main(int argc, char **argv)
{
  unsigned int match;

  PROGRAM = *argv;
  if (argc != 2) die_usage();

  djbio_puts(djbiofd_out, "#\n# WARNING: This file was auto-generated.\n#\n");

  djbio_put(djbiofd_out, "+", 1);
  if (!stralloc_copys(&line, argv[1])) die_nomem();
  stralloc_lower(&line);
  djbio_putsa(djbiofd_out, &line);

  match = 1;
  while (match) {
    line_num++;
    if (getln(djbiofd_in, &line, &match, '\n') < 0) {
      if (errno == error_intr) continue;
      die_syntax_error("input error");
    }
    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) continue;
    if (line.s[0] == '#') continue;
    djbio_put(djbiofd_out, ":", 1);
    djbio_putsa(djbiofd_out, &line);
  }
  djbio_puteol(djbiofd_out);
  djbio_flush(djbiofd_out);

  _exit(0);
}
