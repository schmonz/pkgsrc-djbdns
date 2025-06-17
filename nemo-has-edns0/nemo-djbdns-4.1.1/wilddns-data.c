#include <nemo/exit.h>
#include <nemo/cdb_make.h>
#include <nemo/open.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/getln.h>
#include <nemo/byte.h>
#include <nemo/scan.h>
#include <nemo/ip4.h>
#include <nemo/unix.h>
#include <nemo/error.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "die.h"
#include "whitespace.h"

static const char FN_DATA[] = "data";
static const char FN_CDB[] = "data.cdb";
static const char FN_TMP[] = "data.cdb.tmp";

static int fd;
static djbio io_in;
static char bspace[1024];

static int fd_cdb;
struct cdb_make cdb;

static stralloc line = STRALLOC;
static unsigned int match = 1;
static unsigned int line_num = 0;

static stralloc empty = STRALLOC;

static sa_vector fields = SA_VECTOR;
static stralloc *f;

static dns_domain fqdn = DNS_DOMAIN;

static void die_syntax_error(const char *why)
{
  die_syntax(line_num, why);
}

static void die_datatmp(void)
{
  die_create(FN_TMP);
}

static void check_wildcard_labels(const stralloc *in)
{
  if (stralloc_chr(in, '*') != in->len) die_syntax_error("wildcard prohibited");
}

static void pad_fields(unsigned int required, sa_vector *v)
{
  while (v->len < required) {
    if (!sa_vector_append(v, &empty)) die_nomem();
  }
}

static void domain_parse(dns_domain *d, const stralloc *sa)
{
  if (!dns_domain_fromdot(d, sa->s, sa->len)) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_syntax_error("invalid fqdn");
    die_internal();
  }
}

static void ip4_parse(stralloc *sa, ip4_address *ip)
{
  unsigned int len;
  ip4_zero(ip);
  if (!sa->len) return;
  if (!stralloc_0(sa)) die_nomem();
  len = ip4_scan(ip, sa->s);
  if (len + 1 != sa->len) die_syntax_error("malformed IPv4 address");
}

static void ip6_parse(stralloc *sa, ip6_address *ip)
{
  unsigned int len;
  ip6_zero(ip);
  if (!sa->len) return;
  if (!stralloc_0(sa)) die_nomem();
  len = ip6_scanbracket(ip, sa->s);
  if (len + 1 != sa->len) die_syntax_error("malformed IPv6 address");
}

int main(int argc __UNUSED__, char **argv)
{
  ip4_address ip4;
  ip6_address ip6;
  byte_t data[20];
  char action;

  PROGRAM = *argv;
  umask(022);

  if (!stralloc_erase(&empty)) die_nomem();

  fd = open_read(FN_DATA);
  if (fd < 0) die_open(FN_DATA);
  djbio_initread(&io_in, read, fd, bspace, sizeof bspace);

  fd_cdb = open_trunc(FN_TMP);
  if (fd_cdb < 0) die_datatmp();
  if (cdb_make_start(&cdb, fd_cdb) < 0) die_datatmp();

  while (match) {
    ++line_num;
    if (getln(&io_in, &line, &match, '\n') < 0) die_read_line(line_num);

    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) continue;
    action = line.s[0];
    if (action == '#') continue;

    if (action != '+') die_syntax_error("unrecognized leading character");

    stralloc_remove(&line, 0, 1);
    stralloc_lower(&line);

    if (!sa_vector_parse_config(&fields, &line)) {
      if (errno == error_proto) die_syntax_error("malformed field (octal or IPv6)");
      if (errno == error_nomem) die_nomem();
      die_internal();
    }
    pad_fields(3, &fields);
    f = fields.va;

    check_wildcard_labels(&f[0]);
    domain_parse(&fqdn, &f[0]);

    ip4_parse(&f[1], &ip4);
    ip4_pack(&ip4, data);

    ip6_parse(&f[2], &ip6);
    ip6_pack(&ip6, data + 4);

    if (cdb_make_add(&cdb, fqdn.data, fqdn.len, data, 20) < 0) die_datatmp();
  }

  if (cdb_make_finish(&cdb) < 0) die_datatmp();
  if (fsync(fd_cdb) < 0) die_datatmp();
  if (close(fd_cdb) < 0) die_datatmp();  /* NFS stupidity */
  if (rename(FN_TMP, FN_CDB) < 0) die_move(FN_TMP, FN_CDB);

  _exit(0);
}
