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
#include <nemo/ip6.h>
#include <nemo/unix.h>
#include <nemo/macro_unused.h>

#include "rbldns6.h"
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
  ip4_address return_ip;
  ip6_address ip;
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
        j = byte_chr(line.s + 1, line.len - 1, ':');
        if (j >= line.len - 1) die_syntax_error("missing colon");
        if (ip4_scan(&return_ip, line.s + 1) != j) die_syntax_error("malformed IPv4 address");
        if (!stralloc_copyb(&tmp, return_ip.d, 4)) die_nomem();
        if (!stralloc_catb(&tmp, line.s + j + 2, line.len - j - 2)) die_nomem();
        if (cdb_make_add(&cdb, "", 0, tmp.s, tmp.len) < 0) die_datatmp();
        break;
      case '[':
        if (!stralloc_0(&line)) die_nomem();
        j = ip6_scanbracket(&ip, line.s);
        if (!j) die_syntax_error("malformed IPv6 address");
        switch (line.s[j]) {
          case '/':  /* mask specified */
	    j++;  /* skip '/' */
	    j += scan_uint(line.s + j, &u);
	    if (line.s[j] != '\0') die_syntax_error("malformed IP mask");
            break;
          case '\0':  /* no mask */
            u = 128;
            break;
          default:
            die_syntax_error("malformed IP mask");
            break;
        }
        if (u < 8) die_syntax_error("IP mask too small");
        if (u > 128) die_syntax_error("IP mask too large");
        if (u > RBLDNS6_MAX_MASK) {
          u = RBLDNS6_MAX_MASK;
        }
        ip6_mask_0(&ip, u);
        if (!stralloc_copyb(&tmp, ip.d, RBLDNS6_MAX_BYTES)) die_nomem();  /* only first RBLDNS6_MAX_BYTES bytes */
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
  if (close(fdcdb) < 0) die_datatmp(); /* NFS stupidity */
  if (rename("data.cdb.tmp", "data.cdb") < 0) die_move("data.cdb.tmp", "data.cdb");
  _exit(0);
}
