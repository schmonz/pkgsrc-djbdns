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

static int fd;
static djbio io_in;
static char bspace[1024];

static int fd_cdb;
struct cdb_make cdb;

static stralloc line = STRALLOC;
static unsigned int match = 1;
static unsigned int line_num = 0;

static dns_domain d = DNS_DOMAIN;

static sa_vector fields = SA_VECTOR;

static stralloc data = STRALLOC;

static void die_syntax_error(const char *why)
{
  die_syntax(line_num, why);
}

static void die_fqdnerror(void)
{
  if (errno == error_nomem) die_nomem();
  if (errno == error_proto) die_syntax_error("invalid fqdn");
  die_internal();
}

static void die_datatmp(void)
{
  die_create("data.cdb.tmp");
}

static void check_wildcard_labels(const stralloc *in)
{
  if (stralloc_chr(in, '*') != in->len) die_syntax_error("wildcard prohibited");
}

int main(int argc __UNUSED__, char **argv)
{
  unsigned int i;
  unsigned int j;
  stralloc *f;
  stralloc *fqdn;
  stralloc *sa;
  ip6_address ip;
  byte_t buf[16];
  char action;

  PROGRAM = *argv;
  umask(022);

  fd = open_read("data");
  if (fd < 0) die_open("data");
  djbio_initread(&io_in, read, fd, bspace, sizeof bspace);

  fd_cdb = open_trunc("data.cdb.tmp");
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
    if (fields.len < 2) die_syntax_error("insufficient fields");
    fqdn = f = fields.va;

    check_wildcard_labels(fqdn);

    if (!dns_domain_fromdot(&d, fqdn->s, fqdn->len)) die_fqdnerror();

    if (!stralloc_erase(&data)) die_nomem();
    for (i = 1; i < fields.len; i++) {
      sa = &f[i];
      if (!sa->len) continue;
      if (!stralloc_0(sa)) die_nomem();
      j = ip6_scanbracket(&ip, sa->s);
      if (!j || sa->s[j]) die_syntax_error("invalid IPv6 address");
      ip6_pack(&ip, buf);
      if (!stralloc_catb(&data, buf, sizeof(buf))) die_nomem();
    }

    if (cdb_make_add(&cdb, d.data, d.len, data.s, data.len) < 0) die_datatmp();
  }

  if (cdb_make_finish(&cdb) < 0) die_datatmp();
  if (fsync(fd_cdb) < 0) die_datatmp();
  if (close(fd_cdb) < 0) die_datatmp();  /* NFS stupidity */
  if (rename("data.cdb.tmp", "data.cdb") < 0) die_move("data.cdb.tmp", "data.cdb");

  _exit(0);
}
