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
static stralloc tmp = STRALLOC;

static stralloc line = STRALLOC;
static unsigned int match = 1;
static unsigned int line_num = 0;

static dns_domain d = DNS_DOMAIN;

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
  static sa_vector labels = SA_VECTOR;

  unsigned int i;
  stralloc *sa;

  if (!sa_vector_parse(&labels, in, ".", 1)) die_nomem();
  for (i = 0; i < labels.len; i++) {
    sa = &labels.va[i];
    if (stralloc_chr(sa, '*') == sa->len) continue;
    if (stralloc_len(sa) > 1) die_syntax_error("invalid wildcard");
  }
}

int main(int argc __UNUSED__, char **argv)
{
  ip4_address ip;
  unsigned int j;
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

    stralloc_remove(&line, 0, 1);
    switch (action) {
      case ':':
        j = byte_chr(line.s, line.len, ':');
        if (j >= line.len) die_syntax_error("missing colon");
        if (ip4_scan(&ip, line.s) != j) die_syntax_error("malformed IP address");
        if (!stralloc_copyb(&tmp, ip.d, 4)) die_nomem();
        if (!stralloc_catb(&tmp, line.s + j + 1, line.len - j - 1)) die_nomem();
        if (cdb_make_add(&cdb, "", 0, tmp.s, tmp.len) < 0) die_datatmp();
        break;
      case '+':
        check_wildcard_labels(&line);
        if (!dns_domain_fromdot(&d, line.s, line.len)) die_fqdnerror();
        if (cdb_make_add(&cdb, d.data, d.len, "", 0) < 0) die_datatmp();
        break;
      default:
        die_syntax_error("unrecognized leading character");
    }
  }

  if (cdb_make_finish(&cdb) < 0) die_datatmp();
  if (fsync(fd_cdb) < 0) die_datatmp();
  if (close(fd_cdb) < 0) die_datatmp();  /* NFS stupidity */
  if (rename("data.cdb.tmp", "data.cdb") < 0) die_move("data.cdb.tmp", "data.cdb");

  _exit(0);
}
