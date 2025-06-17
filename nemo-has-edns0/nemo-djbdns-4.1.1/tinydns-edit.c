#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/exit.h>
#include <nemo/open.h>
#include <nemo/getln.h>
#include <nemo/scan.h>
#include <nemo/byte.h>
#include <nemo/str.h>
#include <nemo/fmt.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>
#include <nemo/unix.h>
#include <nemo/error.h>
#include <nemo/sa_vector.h>

#include "dns.h"
#include "die.h"
#include "whitespace.h"

#include <sys/stat.h>

const char USAGE[] = "data data.tmp add [ns|childns|host|alias|mx] domain a.b.c.d";

#define TTL_NS 259200
#define TTL_POSITIVE 86400

static char *fn;
static char *fnnew;

static char mode;
static dns_domain target = DNS_DOMAIN;
static char *target_ipstr;
static ip4_address target_ip4;
static ip6_address target_ip6;

static int fd;
static djbio b;
static char bspace[1024];

static int fdnew;
static djbio bnew;
static char bnewspace[1024];

static stralloc tmp = STRALLOC;

static stralloc line = STRALLOC;
static unsigned int match = 1;

static unsigned int line_num = 0;

static stralloc verb = STRALLOC;

static sa_vector fields = SA_VECTOR;
static stralloc *f;

static dns_domain d1 = DNS_DOMAIN;
static dns_domain d2 = DNS_DOMAIN;
static ip4_address ip4;
static ip6_address ip6;

#define NAMES_SIZE 26
static dns_domain names[NAMES_SIZE];
static int used[NAMES_SIZE];

static void die_syntax_error(const char *what, const stralloc *sa)
{
  static stralloc message = STRALLOC;

  if (!stralloc_copys(&message, what)) die_nomem();
  if (!stralloc_cats(&message, ": ")) die_nomem();
  if (!stralloc_cat(&message, sa)) die_nomem();
  if (!stralloc_0(&message)) die_nomem();
  die_syntax(line_num, message.s);
}

static void put(const char *buf, unsigned int len)
{
  if (djbio_putalign(&bnew, buf, len) < 0) die_write(fnnew);
}

int main(int argc, char **argv)
{
  unsigned long ttl;
  struct stat st;
  unsigned int i;
  char ch;

  PROGRAM = *argv;
  if (argc > 7) die_usage();

  if (!*++argv) die_usage1("missing data filename");
  fn = *argv;

  if (!*++argv) die_usage1("missing temporary filename");
  fnnew = *argv;

  if (!*++argv) die_usage1("missing action");
  if (str_diff(*argv, "add")) die_usage();

  if (!*++argv) die_usage1("missing resource record type");
  if (str_equal(*argv, "ns")) {
    mode = '.';
  }
  else if (str_equal(*argv, "childns")) {
    mode = '&';
  }
  else if (str_equal(*argv, "host")) {
    mode = '=';
  }
  else if (str_equal(*argv, "alias")) {
    mode = '+';
  }
  else if (str_equal(*argv, "mx")) {
    mode = '@';
  }
  else {
    die_usage1("bad resource record type");
  }

  if (!*++argv) die_usage1("missing domain");
  if (!dns_domain_fromdot(&target, *argv, str_len(*argv))) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_parse("bad domain", *argv);
    die_usage();
  }

  if (!*++argv) die_usage1("missing target IP");
  target_ipstr = *argv;
  if (!ip4_scan(&target_ip4, target_ipstr) && !ip6_scan(&target_ip6, target_ipstr)) die_parse("IP", target_ipstr);

  umask(077);

  fd = open_read(fn);
  if (fd < 0) die_read(fn);
  if (fstat(fd, &st) < 0) die_read(fn);
  djbio_initread(&b, read, fd, bspace, sizeof bspace);

  fdnew = open_trunc(fnnew);
  if (fdnew < 0) die_write(fnnew);
  if (fchmod(fdnew, st.st_mode & 0644) < 0) die_write(fnnew);
  djbio_initwrite(&bnew, write, fdnew, bnewspace, sizeof bnewspace);

  switch (mode) {
    case '.':
    case '&':
      ttl = TTL_NS;
      for (i = 0; i < NAMES_SIZE; ++i) {
        ch = (char)('a' + i);
        if (!stralloc_copyb(&tmp, &ch, 1)) die_nomem();
        if (!stralloc_catb(&tmp, ".ns.", 4)) die_nomem();
        if (!dns_domain_todot_cat(&target, &tmp)) die_nomem();
        if (!dns_domain_fromdot(&names[i], tmp.s, tmp.len)) die_nomem();
      }
      break;
    case '+':
    case '=':
      ttl = TTL_POSITIVE;
      break;
    case '@':
      ttl = TTL_POSITIVE;
      for (i = 0; i < NAMES_SIZE; ++i) {
        ch = (char)('a' + i);
        if (!stralloc_copyb(&tmp, &ch, 1)) die_nomem();
        if (!stralloc_catb(&tmp, ".mx.", 4)) die_nomem();
        if (!dns_domain_todot_cat(&target, &tmp)) die_nomem();
        if (!dns_domain_fromdot(&names[i], tmp.s, tmp.len)) die_nomem();
      }
      break;
    default:
      break;
  }

  while (match) {
    ++line_num;
    if (getln(&b, &line, &match, '\n') < 0) die_read_line(line_num);

    put(line.s, line.len);
    if (line.len && !match) {
      put("\n", 1);
    }

    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) continue;
    if (line.s[0] == '#') continue;

    if (!sa_vector_parse_config(&fields, &line)) {
      if (errno == error_proto) die_syntax_error("malformed field (octal or IPv6)", &line);
      if (errno == error_nomem) die_nomem();
      die_internal();
    }
    if (fields.len < 2) die_syntax_error("insufficient fields", &line);
    if (!stralloc_copy(&verb, &fields.va[0])) die_nomem();
    stralloc_upper(&verb);
    sa_vector_remove(&fields, 0, 1);  /* remove verb */
    f = fields.va;

    switch (mode) {
      case '.':
      case '&':
        if (verb.s[0] == mode) {
          if (!dns_domain_fromdot(&d1, f[0].s, f[0].len)) die_nomem();
          if (dns_domain_equal(&d1, &target)) {
            if (stralloc_chr(&f[4], '.') == f[2].len) {
              if (!stralloc_catb(&f[4], ".ns.", 4)) die_nomem();
              if (!stralloc_cat(&f[4], &f[0])) die_nomem();
            }
            if (!dns_domain_fromdot(&d2, f[4].s, f[4].len)) die_nomem();
            if (!stralloc_0(&f[1])) die_nomem();
            if (!scan_ulong(f[1].s, &ttl)) {
              ttl = TTL_NS;
            }
            for (i = 0; i < NAMES_SIZE; ++i) {
              if (dns_domain_equal(&d2, &names[i])) {
                used[i] = 1;
                break;
              }
            }
          }
        }
        break;

      case '=':
        if (verb.s[0] == '=') {
          if (!dns_domain_fromdot(&d1, f[0].s, f[0].len)) die_nomem();
          if (dns_domain_equal(&d1, &target)) die_syntax(line_num, "host name already used");
          for (i = 4; i < fields.len; i++) {
          if (!stralloc_0(&f[4])) die_nomem();
	    if (ip4_scan(&ip4, f[4].s)) {
	      if (ip4_equal(&ip4, &target_ip4)) die_syntax(line_num, "IPv4 address already used");
	    }
	    else if (ip6_scanbracket(&ip6, f[4].s)) {
	      if (ip6_equal(&ip6, &target_ip6)) die_syntax(line_num, "IPv6 address already used");
	    }
          }
        }
        break;

      case '@':
        if (verb.s[0] == '@') {
          if (!dns_domain_fromdot(&d1, f[0].s, f[0].len)) die_nomem();
          if (dns_domain_equal(&d1, &target)) {
            if (stralloc_chr(&f[4], '.') == f[4].len) {
              if (!stralloc_catb(&f[4], ".mx.", 4)) die_nomem();
              if (!stralloc_catb(&f[4], f[0].s, f[0].len)) die_nomem();
            }
            if (!dns_domain_fromdot(&d2, f[4].s, f[4].len)) die_nomem();
            if (!stralloc_0(&f[2])) die_nomem();
            if (!scan_ulong(f[2].s, &ttl)) {
              ttl = TTL_POSITIVE;
            }
            for (i = 0; i < NAMES_SIZE; ++i) {
              if (dns_domain_equal(&d2, &names[i])) {
                used[i] = 1;
                break;
              }
            }
          }
        }
        break;
      default:
        break;
    }
  }

  if (!stralloc_copyb(&tmp, &mode, 1)) die_nomem();
  if (!stralloc_append(&tmp, ":")) die_nomem();
  if (!dns_domain_todot_cat(&target, &tmp)) die_nomem();
  if (!stralloc_append(&tmp, ":")) die_nomem();
  if (!stralloc_catulong(&tmp, ttl)) die_nomem();
  if (!stralloc_append(&tmp, ":")) die_nomem();
  /* no timestamp */
  if (!stralloc_append(&tmp, ":")) die_nomem();
  /* no location */
  if (!stralloc_append(&tmp, ":")) die_nomem();
  switch (mode) {
    case '.':
    case '&':
    case '@':
      if (mode == '@') {
        /* null distance */
        if (!stralloc_append(&tmp, ":")) die_nomem();
      }
      for (i = 0; i < NAMES_SIZE; ++i) {
        if (!used[i]) break;
      }
      if (i >= NAMES_SIZE) die_syntax(line_num, "too many records for that domain");
      ch = (char)('a' + i);
      if (!stralloc_append(&tmp, &ch)) die_nomem();
      if (!stralloc_append(&tmp, ":")) die_nomem();
      break;
    default:  /* '+' '=' */
      break;
  }
  if (!stralloc_cats(&tmp, target_ipstr)) die_nomem();
  if (!stralloc_append(&tmp, "\n")) die_nomem();
  put(tmp.s, tmp.len);

  if (djbio_flush(&bnew) < 0) die_write(fnnew);
  if (fsync(fdnew) < 0) die_write(fnnew);
  if (close(fdnew) < 0) die_write(fnnew);  /* NFS dorks */
  if (rename(fnnew, fn) < 0) die_move(fnnew, fn);
  _exit(0);
}
