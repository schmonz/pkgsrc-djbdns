#include <nemo/exit.h>
#include <nemo/cdb_make.h>
#include <nemo/open.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/getln.h>
#include <nemo/unix.h>
#include <nemo/error.h>
#include <nemo/strerr.h>
#include <nemo/fmt.h>
#include <nemo/env.h>

#include "dns.h"
#include "die.h"
#include "whitespace.h"

const char USAGE[] = "ip [...]";  /* global */

static unsigned int line_num = 0;

static stralloc fqdn = STRALLOC;
static stralloc tmp = STRALLOC;

static ip4_vector servers = IP4_VECTOR;

static char ip4str[IP4_FMT];

static void die_syntax_error(const char *why)
{
  die_syntax(line_num, why);
}

static void log_fqdn_error(void)
{
  char strnum[FMT_ULONG];

  strnum[fmt_ulong(strnum, line_num)] = '\0';
  if (!stralloc_copy(&tmp, &fqdn)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  strerr_warn5sys("error: line=", strnum, " fqdn=", tmp.s, "; NS error");
}

static void log_ip_error(const stralloc *name)
{
  char strnum[FMT_ULONG];

  strnum[fmt_ulong(strnum, line_num)] = '\0';
  if (!stralloc_copy(&tmp, name)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  strerr_warn5sys("error: line=", strnum, " server=", tmp.s, "; NS error");
}

static unsigned int get_ips(void)
{
  static sa_vector names = SA_VECTOR;
  static ip4_vector ips = IP6_VECTOR;
  register unsigned int i;
  stralloc *name;

  if (dns4_ns(&names, &fqdn) < 0) {
    log_fqdn_error();
    return 0;
  }

  if (!ip4_vector_erase(&servers)) die_nomem();
  for (i = 0; i < names.len; i++) {
    name = &names.va[i];
    if (dns4_ip4(&ips, name) < 0) {
      log_ip_error(name);
      continue;
    }
    if (!ip4_vector_cat(&servers, &ips)) die_nomem();
  }
  return servers.len;
}

int main(int argc, char **argv)
{
  register unsigned int i;
  char seed[128];
  int k;
  unsigned int match;

  PROGRAM = *argv;
  if (argc < 2) die_usage();

  dns_random_init(seed);

  if (!stralloc_copys(&fqdn, argv[1])) die_nomem();
  for (k = 2; k < argc; k++) {
    if (!stralloc_append(&fqdn, " ")) die_nomem();
    if (!stralloc_cats(&fqdn, argv[k])) die_nomem();
  }
  if (!stralloc_0(&fqdn)) die_nomem();
  env_put2("DNSCACHEIP", fqdn.s);

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

    if (!get_ips()) continue;

    djbio_put(djbiofd_out, "+", 1);
    djbio_putsa(djbiofd_out, &fqdn);
    for (i = 0; i < servers.len; i++) {
      djbio_put(djbiofd_out, ":", 1);
      djbio_put(djbiofd_out, ip4str, ip4_fmt(&servers.va[i], ip4str));
    }
    djbio_puteol(djbiofd_out);
  }
  djbio_flush(djbiofd_out);

  _exit(0);
}
