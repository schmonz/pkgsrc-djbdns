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
#include <nemo/macro_unused.h>

#include "die.h"
#include "whitespace.h"

static int fd;
static djbio io_in;
static byte_t bspace[1024];

static int fdcdb;
struct cdb_make cdb;
static stralloc tmp = STRALLOC;

static stralloc line = STRALLOC;
static unsigned int match = 1;
static unsigned int line_num = 0;

static void die_syntax_error(const char *why)
{
  die_syntax(line_num, why);
}

static void die_datatmp(void)
{
  die_create("data.cdb.tmp");
}

int main(int argc __UNUSED__, char **argv)
{
  ip4_address ip;
  unsigned int u;
  unsigned int j;
  byte_t ch;
  char action;

  PROGRAM = *argv;
  umask(022);

  fd = open_read("data");
  if (fd < 0) die_open("data");
  djbio_initread(&io_in, read, fd, bspace, sizeof bspace);

  fdcdb = open_trunc("data.cdb.tmp");
  if (fdcdb < 0) die_datatmp();
  if (cdb_make_start(&cdb, fdcdb) < 0) die_datatmp();

  while (match) {
    ++line_num;
    if (getln(&io_in, &line, &match, '\n') < 0) die_read_line(line_num);

    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) continue;
    action = line.s[0];
    if (action == '#') continue;

    switch (action) {
      case ':':
        stralloc_remove(&line, 0, 1);
        j = byte_chr(line.s, line.len, ':');
        if (j >= line.len) die_syntax_error("missing colon");
        if (ip4_scan(&ip, line.s) != j) die_syntax_error("malformed IP address");
        if (!stralloc_copyb(&tmp, ip.d, 4)) die_nomem();
        if (!stralloc_catb(&tmp, line.s + j + 1, line.len - j - 1)) die_nomem();
        if (cdb_make_add(&cdb, "", 0, tmp.s, tmp.len) < 0) die_datatmp();
        break;
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        if (!stralloc_0(&line)) die_nomem();
        if (!ip4_mask_scan(&ip, &u, line.s)) die_syntax_error("malformed IP address mask");
        if (u < 8) die_syntax_error("IP mask too small");
        if (u > 32) die_syntax_error("IP mask too large");
        ip4_mask_0(&ip, u);
        if (!stralloc_copyb(&tmp, ip.d, 4)) die_nomem();
        ch = (byte_t)u;
        if (!stralloc_append(&tmp, &ch)) die_nomem();
        if (cdb_make_add(&cdb, tmp.s, tmp.len, "", 0) < 0) die_datatmp();
        break;
      default:
        die_syntax_error("unrecognized leading character");
    }
  }

  if (cdb_make_finish(&cdb) < 0) die_datatmp();
  if (fsync(fdcdb) < 0) die_datatmp();
  if (close(fdcdb) < 0) die_datatmp();  /* NFS stupidity */
  if (rename("data.cdb.tmp", "data.cdb") < 0) die_move("data.cdb.tmp", "data.cdb");
  _exit(0);
}
