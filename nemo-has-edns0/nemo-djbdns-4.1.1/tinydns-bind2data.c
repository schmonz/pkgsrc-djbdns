#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/exit.h>
#include <nemo/char.h>
#include <nemo/scan.h>
#include <nemo/stralloc.h>
#include <nemo/sa_vector.h>
#include <nemo/sa_stream.h>
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
static sa_stream line_stream;

static sa_vector fields = SA_VECTOR;
static stralloc *f;

static stralloc *rr_name;
static stralloc *rr_ttl;
static stralloc *rr_class;
static stralloc *rr_type;

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
  register unsigned int i;
  register const char *x;

  x = sa->s;
  for (i = 0; i < sa->len; i++) {
    if (*x == ':') {
      djbio_put(djbiofd_out, "\\072", 4);
    }
    else if ((*x < ' ') || (*x > '~')) {
      djbio_put(djbiofd_out, "\\", 1);
      djbio_put(djbiofd_out, &char_hex_chars[(*x >> 6) & 0x7], 1);
      djbio_put(djbiofd_out, &char_hex_chars[(*x >> 3) & 0x7], 1);
      djbio_put(djbiofd_out, &char_hex_chars[*x & 0x7], 1);
    }
    else {
      djbio_put(djbiofd_out, x, 1);
    }
    x++;
  }
}

static void trim_domain_dot(stralloc *dn)
{
  if (stralloc_len(dn) > 1) {
    stralloc_trim(dn, ".", 1);
  }
  stralloc_lower(dn);
}

static unsigned long timestamp_parse(stralloc *sa, const char *errmsg)
{
  static stralloc tmp = STRALLOC;
  struct caltime ct;
  struct tai t;
  uint64_t u;

  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (scan_uint64(tmp.s, &u) != sa->len) die_syntax_error(errmsg, sa);

  if (sa->len == 14) {  /* YYYYMMDDHHmmSS */
    ct.offset = 0;
    ct.second = (int)(u % 100);
    u /= 100;
    ct.minute = (int)(u % 100);
    u /= 100;
    ct.hour = (int)(u % 100);
    u /= 100;
    ct.date.day = (int)(u % 100);
    u /= 100;
    ct.date.month = (int)(u % 100);
    u /= 100;
    ct.date.year = (int)(u);
    caltime_tai(&ct, &t);
    return (unsigned long)tai_epoch(&t);
  }

  if (sa->len > 10) die_syntax_error(errmsg, sa);

  return (unsigned long)u;
}

static const char *security_algorithm_parse(stralloc *sa)
{
  static stralloc tmp = STRALLOC;

  unsigned int u;

  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (scan_uint(tmp.s, &u) != sa->len) die_syntax_error(SECURITY_ALGORITHM_MSG, sa);

  if (u == 1) return "RSAMD5";
  if (u == 2) return "DH";
  if (u == 3) return "DSA";
  if (u == 4) return "ECC";
  if (u == 5) return "RSASHA1";
  if (u == 6) return "DSA-NSEC3-SHA1";
  if (u == 7) return "RSASHA1-NSEC3-SHA1";
  if (u == 8) return "RSASHA256";
  if (u == 10) return "RSASHA512";
  if (u == 12) return "ECC-GOST";
  if (u == 13) return "ECDSAP256SHA256";
  if (u == 14) return "ECDSAP384SHA384";
  if (u == 15) return "ED25519";
  if (u == 16) return "ED448";
  if (u == 252) return "INDIRECT";
  if (u == 253) return "PRIVATEDNS";
  if (u == 254) return "PRIVATEOID";

  die_syntax_error(SECURITY_ALGORITHM_MSG, sa);
  return 0;
}

static const char *dnssec_digest_type_parse(stralloc *sa)
{
  static stralloc tmp = STRALLOC;

  unsigned int u;

  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (scan_uint(tmp.s, &u) != sa->len) die_syntax_error(DIGEST_TYPE_MSG, sa);

  if (u == 1) return "SHA1";
  if (u == 2) return "SHA256";
  if (u == 3) return "GOST";
  if (u == 4) return "SHA384";

  die_syntax_error(DIGEST_TYPE_MSG, sa);
  return 0;
}

/*
  data:    aaa   "bbb ccc"   ddd
  state: 0 111 0 222222222 0 111

  assumption: no leading white space
*/
static unsigned int line_parse(void)
{
  static stralloc tmp = STRALLOC;
  unsigned int state;
  char ch;

  if (!stralloc_erase(&tmp)) die_nomem();
  if (!sa_vector_erase(&fields)) die_nomem();

  state = 0;
  sa_stream_init(&line_stream, &line);
  while (sa_stream_getc(&line_stream, &ch)) {
    if (ch == ' ' || ch == '\t') {
      switch (state) {
        case 0:  /* prev == white space */
          break;
        case 1:  /* prev == token */
          if (!sa_vector_append(&fields, &tmp)) die_nomem();
          if (!stralloc_erase(&tmp)) die_nomem();
          state = 0;
          break;
        case 2:  /* prev == inside quotes */
          if (!stralloc_append(&tmp, &ch)) die_nomem();
          break;
        default:
          break;
      }
      continue;
    }
    if (ch == '"') {
      switch (state) {
        case 0:  /* prev == white space */
          state = 2;  /* inside quotes */
          break;
        case 1:  /* prev == token */
          die_syntax_error("format error", &line);
          break;
        case 2:  /* prev == inside quotes */
          if (!sa_vector_append(&fields, &tmp)) die_nomem();
          if (!stralloc_erase(&tmp)) die_nomem();
          state = 0;
          break;
        default:
          break;
      }
      continue;
    }
    if (ch == ';') {
      if (state != 2) break;  /* not inside quotes */
    }
    if (!state) {  /* prev == white space */
	state = 1;  /* inside token */
    }
    /* prev == token */
    /* prev == inside quotes */
    if (!stralloc_append(&tmp, &ch)) die_nomem();
  }
  if (stralloc_len(&tmp)) {
    if (!sa_vector_append(&fields, &tmp)) die_nomem();
  }

  if (!fields.len) return 0;

  if (fields.len < 5) die_syntax_error("format error", &line);

  f = fields.va;
  rr_name = &f[0];
  rr_ttl = &f[1];
  rr_class = &f[2];
  rr_type = &f[3];

  trim_domain_dot(rr_name);
  stralloc_upper(rr_class);
  stralloc_upper(rr_type);

  return 1;
}

static void do_rr_soa(void)
{
  register unsigned int i;

  pad_fields(11);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  trim_domain_dot(&f[4]);
  trim_domain_dot(&f[5]);
  for (i = 4; i < 11; i++) {
    output_colon();
    output_sa(&f[i]);
  }
  djbio_puteol(djbiofd_out);
}

static void do_rr_ns(void)
{
  pad_fields(5);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  trim_domain_dot(&f[4]);
  output_sa(&f[4]);
  djbio_puteol(djbiofd_out);
}

static void do_rr_a(void)
{
  pad_fields(5);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  output_sa(&f[4]);
  djbio_puteol(djbiofd_out);
}

static void do_rr_aaaa(void)
{
  pad_fields(5);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  djbio_put(djbiofd_out, "[" , 1);
  output_sa(&f[4]);
  djbio_put(djbiofd_out, "]" , 1);
  djbio_puteol(djbiofd_out);
}

static void do_rr_cname(void)
{
  pad_fields(5);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  trim_domain_dot(&f[4]);
  output_sa(&f[4]);
  djbio_puteol(djbiofd_out);
}

static void do_rr_ptr(void)
{
  pad_fields(5);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  trim_domain_dot(&f[4]);
  output_sa(&f[4]);
  djbio_puteol(djbiofd_out);
}

static void do_rr_txt(void)
{
  register unsigned int i;

  pad_fields(5);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  for (i = 4; i < fields.len; i++) {
    output_colon();
    output_text(&f[i]);
  }
  djbio_puteol(djbiofd_out);
}

static void do_rr_mx(void)
{
  pad_fields(6);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  output_sa(&f[4]);  /* dist */
  output_colon();
  trim_domain_dot(&f[5]);
  output_sa(&f[5]);  /* fqdn */
  output_colon();
  /* no ip */
  djbio_puteol(djbiofd_out);
}

static void do_rr_srv(void)
{
  pad_fields(8);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  /* no ip */
  output_colon();
  output_sa(&f[0]);  /* weight */
  output_colon();
  output_sa(&f[1]);  /* priority */
  output_colon();
  output_sa(&f[2]);  /* port */
  output_colon();
  trim_domain_dot(&f[3]);
  output_sa(&f[3]);  /* target */
  djbio_puteol(djbiofd_out);
}

static void do_rr_naptr(void)
{
  pad_fields(10);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  output_sa(&f[4]);  /* order */
  output_colon();
  output_sa(&f[5]);  /* pref */
  output_colon();
  output_sa(&f[6]);  /* flags */
  output_colon();
  output_sa(&f[7]);  /* service */
  output_colon();
  output_text(&f[8]);  /* regex */
  output_colon();
  trim_domain_dot(&f[9]);
  output_sa(&f[9]);  /* replacement */

  djbio_puteol(djbiofd_out);
}

static void do_rr_caa(void)
{
  pad_fields(7);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  output_sa(&f[4]);  /* flags */
  output_colon();
  stralloc_lower(&f[5]);
  output_sa(&f[5]);  /* tag */
  output_colon();
  output_text(&f[6]);  /* value */
  output_colon();
  djbio_puteol(djbiofd_out);
}

static void do_rr_dnskey(void)
{
  pad_fields(8);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  output_sa(&f[4]);  /* flags */
  output_colon();
  output_sa(&f[5]);  /* protocol */
  output_colon();
  djbio_puts(djbiofd_out, security_algorithm_parse(&f[6]));
  output_colon();
  output_sa(&f[7]);  /* public key */
  djbio_puteol(djbiofd_out);
}

static void do_rr_rrsig(void)
{
  pad_fields(13);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  stralloc_upper(&f[4]);
  output_sa(&f[4]);  /* RR type covered */
  output_colon();
  djbio_puts(djbiofd_out, security_algorithm_parse(&f[5]));
  output_colon();
  output_sa(&f[6]);  /* label count in rr_name */
  output_colon();
  output_sa(&f[7]);  /* TTL of original RR set */
  output_colon();
  output_number(timestamp_parse(&f[8], "malformed expiration timestamp"));
  output_colon();
  output_number(timestamp_parse(&f[9], "malformed inception timestamp"));
  output_colon();
  output_sa(&f[10]);  /* key tag */
  output_colon();
  trim_domain_dot(&f[11]);
  output_sa(&f[11]);  /* name of signer */
  output_colon();
  output_sa(&f[12]);  /* signature */
  djbio_puteol(djbiofd_out);
}

static void do_rr_nsec(void)
{
  unsigned int i;

  pad_fields(5);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  trim_domain_dot(&f[4]);
  output_sa(&f[4]);  /* next authoritative name */
  for (i = 5; i < fields.len; i++) {
    output_colon();
    stralloc_upper(&f[i]);
    output_text(&f[i]);  /* RR type covered */
  }
  djbio_puteol(djbiofd_out);
}

static void do_rr_ds(void)
{
  pad_fields(8);
  output_sa(rr_type);
  output_colon();
  output_sa(rr_name);
  output_colon();
  output_sa(rr_ttl);
  output_colon();
  /* no timestamp */
  output_colon();
  /* no location */
  output_colon();
  output_sa(&f[4]);  /* key tag */
  output_colon();
  djbio_puts(djbiofd_out, security_algorithm_parse(&f[5]));
  output_colon();
  djbio_puts(djbiofd_out, dnssec_digest_type_parse(&f[6]));
  output_colon();
  output_sa(&f[7]);  /* digest */
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
int main(int argc __UNUSED__, char **argv)
{
  unsigned int match;

  PROGRAM = *argv;

  if (!stralloc_erase(&empty)) die_nomem();

  djbio_puts(djbiofd_out, "#\n# WARNING: This file was auto-generated.\n#\n");

  match = 1;
  while (match) {
    ++line_num;
    if (getln(djbiofd_in, &line, &match, '\n') < 0) die_read_line(line_num);

    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) continue;

    if (!line_parse()) continue;

    if (stralloc_diffs(rr_class, "IN")) die_syntax_error("invalid class", rr_class);

    if (stralloc_equals(rr_type, "NS")) {
      if (!stralloc_copys(rr_type, "&")) die_nomem();
      do_rr_ns();
      continue;
    }
    if (stralloc_equals(rr_type, "A")) {
      if (!stralloc_copys(rr_type, "+")) die_nomem();
      do_rr_a();
      continue;
    }
    if (stralloc_equals(rr_type, "AAAA")) {
      if (!stralloc_copys(rr_type, "+")) die_nomem();
      do_rr_aaaa();
      continue;
    }
    if (stralloc_equals(rr_type, "MX")) {
      if (!stralloc_copys(rr_type, "@")) die_nomem();
      do_rr_mx();
      continue;
    }
    if (stralloc_equals(rr_type, "TXT")) {
      if (!stralloc_copys(rr_type, "'")) die_nomem();
      do_rr_txt();
      continue;
    }
    if (stralloc_equals(rr_type, "CNAME")) {
      do_rr_cname();
      continue;
    }
    if (stralloc_equals(rr_type, "PTR")) {
      if (!stralloc_copys(rr_type, "^")) die_nomem();
      do_rr_ptr();
      continue;
    }
    if (stralloc_equals(rr_type, "SOA")) {
      do_rr_soa();
      continue;
    }
    if (stralloc_equals(rr_type, "SRV")) {
      do_rr_srv();
      continue;
    }
    if (stralloc_equals(rr_type, "NAPTR")) {
      do_rr_naptr();
      continue;
    }
    if (stralloc_equals(rr_type, "DNSKEY")) {
      do_rr_dnskey();
      continue;
    }
    if (stralloc_equals(rr_type, "RRSIG")) {
      do_rr_rrsig();
      continue;
    }
    if (stralloc_equals(rr_type, "NSEC")) {
      do_rr_nsec();
      continue;
    }
    if (stralloc_equals(rr_type, "DS")) {
      do_rr_ds();
      continue;
    }
    if (stralloc_equals(rr_type, "CAA")) {
      do_rr_caa();
      continue;
    }
    die_syntax_error("unrecognized type", rr_type);
  }
  djbio_flush(djbiofd_out);

  _exit(0);
}
