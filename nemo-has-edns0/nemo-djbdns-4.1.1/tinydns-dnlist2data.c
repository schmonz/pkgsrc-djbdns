#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/exit.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/getln.h>
#include <nemo/unix.h>
#include <nemo/error.h>
#include <nemo/sgetopt.h>
#include <nemo/scan.h>

#include "dns.h"
#include "die.h"
#include "whitespace.h"

#include <sys/stat.h>

const char USAGE[] = "[ -l TTL ] [-s serial ] [ -f refresh ] [-t retry ] [ -e expiry ][ -m minimum ]";

static unsigned int line_num = 0;

static stralloc line = STRALLOC;

static stralloc rr_ttl = STRALLOC;
static stralloc rr_serial = STRALLOC;
static stralloc rr_refresh_time = STRALLOC;
static stralloc rr_retry_time = STRALLOC;
static stralloc rr_expire_time = STRALLOC;
static stralloc rr_minimum_time = STRALLOC;

static void die_syntax_malformed(const char *what, const char *value)
{
  static stralloc message = STRALLOC;

  if (!stralloc_copys(&message, "malformed ")) die_nomem();
  if (!stralloc_cats(&message, what)) die_nomem();
  if (!stralloc_cats(&message, ": ")) die_nomem();
  if (!stralloc_cats(&message, value)) die_nomem();
  if (!stralloc_0(&message)) die_nomem();
  die_syntax(line_num, message.s);
}

static inline void output_colon(void)
{
  djbio_put(djbiofd_out, ":" , 1);
}
static inline void output_sa(const stralloc *sa)
{
  djbio_putsa(djbiofd_out, sa);
}
static void output_prefix_domain(const char *prefix, const stralloc *domain)
{
  djbio_puts(djbiofd_out, prefix);
  djbio_put(djbiofd_out, ".", 1);
  djbio_putsa(djbiofd_out, domain);
}

static void ulong_parse(const char *in, stralloc *out, const char *errmsg)
{
  unsigned long u;

  if (!*in) die_syntax_malformed(errmsg, in);
  if (in[scan_ulong(in, &u)]) die_syntax_malformed(errmsg, in);
  if (!stralloc_erase(out)) die_nomem();
  if (!stralloc_catulong(out, u)) die_nomem();
}

static void do_rr_soa(void)
{
  djbio_put(djbiofd_out, "SOA" , 3);
  output_colon();
  output_sa(&line);
  output_colon();
  output_sa(&rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  output_prefix_domain("a.ns", &line);
  output_colon();
  output_prefix_domain("hostmaster", &line);
  output_colon();
  output_sa(&rr_serial);
  output_colon();
  output_sa(&rr_refresh_time);
  output_colon();
  output_sa(&rr_retry_time);
  output_colon();
  output_sa(&rr_expire_time);
  output_colon();
  output_sa(&rr_minimum_time);
  djbio_puteol(djbiofd_out);
}

/*
static void do_comment(void)
{
  register unsigned int i;

  pad_fields(1);
  djbio_put(djbiofd_out, "# " , 2);
  output_sa(rr_name);
  output_space();
  output_sa(rr_ttl);
  output_space();
  output_sa(rr_class);
  output_space();
  output_sa(rr_type);
  for (i = 0; i < fields.len; i++) {
    output_space();
    output_sa(&f[i]);
  }
  djbio_puteol(djbiofd_out);
}
*/
static void init_values(void)
{
/*
  allow tinydns-data to generate default values
*/
  if (!stralloc_erase(&rr_ttl)) die_nomem();
  if (!stralloc_erase(&rr_serial)) die_nomem();
  if (!stralloc_erase(&rr_refresh_time)) die_nomem();
  if (!stralloc_erase(&rr_retry_time)) die_nomem();
  if (!stralloc_erase(&rr_expire_time)) die_nomem();
  if (!stralloc_erase(&rr_minimum_time)) die_nomem();
}

int main(int argc, char **argv)
{
  unsigned int match;
  int opt;

  PROGRAM = *argv;

  init_values();

  while ((opt = getopt(argc, argv, "l:s:f:t:e:m:")) != opteof) {
    switch (opt) {
      case 'l':
        ulong_parse(optarg, &rr_ttl, "time to live");
        break;
      case 's':
        ulong_parse(optarg, &rr_serial, "serial");
        break;
      case 'f':
        ulong_parse(optarg, &rr_refresh_time, "refresh time");
        break;
      case 't':
        ulong_parse(optarg, &rr_retry_time, "retry time");
        break;
      case 'e':
        ulong_parse(optarg, &rr_expire_time, "expire time");
        break;
      case 'm':
        ulong_parse(optarg, &rr_minimum_time, "minimum time");
        break;
      default:
        die_usage();
        break;
    }
  }
  argv += optind;

  djbio_puts(djbiofd_out, "#\n# WARNING: This file was auto-generated.\n#\n");

  match = 1;
  while (match) {
    ++line_num;
    if (getln(djbiofd_in, &line, &match, '\n') < 0) die_read_line(line_num);
    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) continue;
    if (line.s[0] == '#') continue;
    stralloc_lower(&line);
    stralloc_trim(&line, ".", 1);  /* should not trailing dot, assume worst */
    do_rr_soa();
  }
  djbio_flush(djbiofd_out);

  _exit(0);
}
