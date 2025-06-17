#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/exit.h>
#include <nemo/char.h>
#include <nemo/scan.h>
#include <nemo/stralloc.h>
#include <nemo/sa_vector.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/getln.h>
#include <nemo/unix.h>
#include <nemo/char.h>
#include <nemo/error.h>
#include <nemo/fmt.h>
#include <nemo/caldate.h>
#include <nemo/caltime.h>
#include <nemo/uint64.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "die.h"
#include "whitespace.h"

#include <sys/stat.h>

static const char SECURITY_ALGORITHM_MSG[] = "invalid security algorithm";
static const char DIGEST_TYPE_MSG[] = "invalid DNSSEC digest type";

static stralloc empty = STRALLOC;

static unsigned int line_num = 0;

static stralloc line = STRALLOC;

static sa_vector fields = SA_VECTOR;
static stralloc *f;

static stralloc rr_type = STRALLOC;
static stralloc *rr_name;

static void die_syntax_error(const char *why, const stralloc *sa)
{
  static stralloc tmp = STRALLOC;

  if (!stralloc_copys(&tmp, why)) die_nomem();
  if (!stralloc_cats(&tmp, ": ")) die_nomem();
  if (!stralloc_cat(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  die_syntax(line_num, tmp.s);
}

static void pad_fields(unsigned int required)
{
  while (fields.len < required) {
    if (!sa_vector_append(&fields, &empty)) die_nomem();
  }
}

static inline void output_type(void)
{
  djbio_putsa(djbiofd_out, &rr_type);
}
static inline void output_colon(void)
{
  djbio_put(djbiofd_out, ":" , 1);
}
static inline void output_space(void)
{
  djbio_put(djbiofd_out, " " , 1);
}
static inline void output_sa(const stralloc *sa)
{
  djbio_putsa(djbiofd_out, sa);
}
static inline void output_number(unsigned long u)
{
  char fmtstr[FMT_ULONG];

  djbio_put(djbiofd_out, fmtstr, fmt_ulong(fmtstr, u));
}
static void output_text(const stralloc *sa)
{
  unsigned int i;
  const char *x;

  x = sa->s;
  for (i = 0; i < sa->len; i++) {
    if (*x == ':') {
      djbio_put(djbiofd_out, "\\072", 4);
    }
    else {
      djbio_put(djbiofd_out, x, 1);
    }
    x++;
  }
}

static unsigned int line_parse(char type)
{
  if (!stralloc_copyb(&rr_type, &type, 1)) die_nomem();
  if (!sa_vector_parse_config(&fields, &line)) {
    if (errno == error_proto) die_syntax_error("malformed field (octal or IPv6)", &line);
    if (errno == error_nomem) die_nomem();
    die_internal();
  }

  if (!fields.len) die_syntax_error("format error", &line);

  f = fields.va;
  rr_name = &f[0];

  stralloc_lower(rr_name);
  stralloc_upper(&rr_type);

  return 1;
}

static void do_rr_soa(void)
{
  pad_fields(11);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[8]);  /* ttl */
  output_colon();
  output_sa(&f[9]);  /* timestamp */
  output_colon();
  output_sa(&f[10]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* primary name server */
  output_colon();
  output_sa(&f[2]);  /* contact address */
  output_colon();
  output_sa(&f[3]);  /* serial number */
  output_colon();
  output_sa(&f[4]);  /* refresh time */
  output_colon();
  output_sa(&f[5]);  /* retry time */
  output_colon();
  output_sa(&f[6]);  /* expire time */
  output_colon();
  output_sa(&f[7]);  /* minimum time */
  djbio_puteol(djbiofd_out);
}

static void do_rr_ns(void)
{
  pad_fields(6);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[3]);  /* ttl */
  output_colon();
  output_sa(&f[4]);  /* timestamp */
  output_colon();
  output_sa(&f[5]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* name server */
  if (f[2].len) {
    output_colon();
    output_sa(&f[2]);  /* ip */
  }
  djbio_puteol(djbiofd_out);
}

static void do_rr_a(void)
{
  pad_fields(5);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[2]);  /* ttl */
  output_colon();
  output_sa(&f[3]);  /* timestamp */
  output_colon();
  output_sa(&f[4]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* IPv4 */
  djbio_puteol(djbiofd_out);
}

static void do_rr_aaaa(void)
{
  pad_fields(5);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[2]);  /* ttl */
  output_colon();
  output_sa(&f[3]);  /* timestamp */
  output_colon();
  output_sa(&f[4]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* IPv6 */
  djbio_puteol(djbiofd_out);
}

static void do_rr_cname(void)
{
  pad_fields(5);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[2]);  /* ttl */
  output_colon();
  output_sa(&f[3]);  /* timestamp */
  output_colon();
  output_sa(&f[4]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* target */
  djbio_puteol(djbiofd_out);
}

static void do_rr_ptr(void)
{
  pad_fields(5);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[2]);  /* ttl */
  output_colon();
  output_sa(&f[3]);  /* timestamp */
  output_colon();
  output_sa(&f[4]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* name */
  djbio_puteol(djbiofd_out);
}

static void do_rr_txt(void)
{
  pad_fields(5);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[2]);  /* ttl */
  output_colon();
  output_sa(&f[3]);  /* timestamp */
  output_colon();
  output_sa(&f[4]);  /* location */
  output_colon();
  output_text(&f[1]);
  djbio_puteol(djbiofd_out);
}

static void do_rr_mx(void)
{
  pad_fields(1);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[4]);  /* ttl */
  output_colon();
  output_sa(&f[5]);  /* timestamp */
  output_colon();
  output_sa(&f[6]);  /* location */
  output_colon();
  output_sa(&f[3]);  /* dist */
  output_colon();
  output_sa(&f[2]);  /* mail exchanger */
  if (f[1].len) {
    output_colon();
    output_sa(&f[1]);  /* IP */
  }
  djbio_puteol(djbiofd_out);
}

static void do_rr_srv(void)
{
  pad_fields(9);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[6]);  /* ttl */
  output_colon();
  output_sa(&f[7]);  /* timestamp */
  output_colon();
  output_sa(&f[8]);  /* location */
  output_colon();
  output_sa(&f[4]);  /* weight */
  output_colon();
  output_sa(&f[5]);  /* priority */
  output_colon();
  output_sa(&f[3]);  /* port */
  output_colon();
  output_sa(&f[2]);  /* target */
  if (f[1].len) {
    output_colon();
    output_sa(&f[1]);  /* IP */
  }
  djbio_puteol(djbiofd_out);
}

static void do_rr_naptr(void)
{
  pad_fields(10);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[7]);  /* ttl */
  output_colon();
  output_sa(&f[8]);  /* timestamp */
  output_colon();
  output_sa(&f[9]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* order */
  output_colon();
  output_sa(&f[2]);  /* pref */
  output_colon();
  output_sa(&f[3]);  /* flags */
  output_colon();
  output_sa(&f[4]);  /* service */
  output_colon();
  output_sa(&f[5]);  /* regex */
  output_colon();
  output_sa(&f[6]);  /* replacement */
  djbio_puteol(djbiofd_out);
}

static void do_rr_generic(void)
{
  pad_fields(6);
  output_type();
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(&f[3]);  /* ttl */
  output_colon();
  output_sa(&f[4]);  /* timestamp */
  output_colon();
  output_sa(&f[5]);  /* location */
  output_colon();
  output_sa(&f[1]);  /* rrtype */
  output_colon();
  output_text(&f[2]);  /* rrdata */
  djbio_puteol(djbiofd_out);
}

static void do_location(void)
{
  register unsigned int i;

  pad_fields(1);
  output_type();
  output_colon();
  output_sa(rr_name);
  for (i = 2; i < fields.len; i++) {
    output_colon();
    output_sa(&f[i]);
  }
  djbio_puteol(djbiofd_out);
}
/*
static void do_comment(void)
{
  register unsigned int i;

  pad_fields(1);
  djbio_put(djbiofd_out, "# " , 2);
  output_type();
  output_colon();
  output_sa(rr_name);
  for (i = 2; i < fields.len; i++) {
    output_colon();
    output_sa(&f[i]);
  }
  djbio_puteol(djbiofd_out);
}
*/
int main(int argc __UNUSED__, char **argv)
{
  unsigned int match;
  char type;

  PROGRAM = *argv;
  umask(022);

  if (!stralloc_erase(&empty)) die_nomem();
/*
  djbio_puts(djbiofd_out, "# generated by ");
  djbio_puts(djbiofd_out, PROGRAM);
  djbio_puteol(djbiofd_out);
*/
  match = 1;
  while (match) {
    ++line_num;
    if (getln(djbiofd_in, &line, &match, '\n') < 0) die_read_line(line_num);
    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) {
      djbio_puteol(djbiofd_out);
      continue;
    }
    type = line.s[0];
    if (type == '#' || type == '-') {
      djbio_putsa(djbiofd_out, &line);
      djbio_puteol(djbiofd_out);
      continue;
    }

    stralloc_remove(&line, 0, 1);  /* remove type char */
    if (!line_parse(type)) continue;

    if (type == '%') {
      do_location();
      continue;
    }
    if (type == '.' || type == '&') {
      do_rr_ns();
      continue;
    }
    if (type == '+' || type == '=') {
      do_rr_a();
      continue;
    }
    if (type == '6') {
      if (!stralloc_copys(&rr_type, "=")) die_nomem();
      do_rr_aaaa();
      continue;
    }
    if (type == '3') {
      if (!stralloc_copys(&rr_type, "+")) die_nomem();
      do_rr_aaaa();
      continue;
    }
    if (type == '@') {
      do_rr_mx();
      continue;
    }
    if (type == '\'') {
      do_rr_txt();
      continue;
    }
    if (type == '^') {
      do_rr_ptr();
      continue;
    }
    if (type == 'C') {
      if (!stralloc_copys(&rr_type, "CNAME")) die_nomem();
      do_rr_cname();
      continue;
    }
    if (type == 'Z') {
      if (!stralloc_copys(&rr_type, "SOA")) die_nomem();
      do_rr_soa();
      continue;
    }
    if (type == 'S') {
      if (!stralloc_copys(&rr_type, "SRV")) die_nomem();
      do_rr_srv();
      continue;
    }
    if (type == 'N') {
      if (!stralloc_copys(&rr_type, "NAPTR")) die_nomem();
      do_rr_naptr();
      continue;
    }
    if (type == ':') {
      if (!stralloc_copys(&rr_type, "?")) die_nomem();
      do_rr_generic();
      continue;
    }
    die_syntax_error("unrecognized type", &rr_type);
  }
  djbio_flush(djbiofd_out);

  _exit(0);
}

