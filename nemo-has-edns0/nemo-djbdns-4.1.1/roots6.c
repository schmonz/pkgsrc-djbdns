#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/open.h>
#include <nemo/error.h>
#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/error.h>
#include <nemo/direntry.h>
#include <nemo/stralloc.h>
#include <nemo/sa_vector.h>
#include <nemo/openreadclose.h>
#include <nemo/unix.h>
#include <nemo/cdb.h>

#include <sys/stat.h>

#include "dns.h"
#include "roots.h"
#include "die.h"

static const char ROOTS_CDB_PATH[] = "servers/data.cdb";

static struct cdb roots6_cdb = CDB;
static int roots6_cdb_fd = -1;
static time_t roots6_cdb_expiry = 0;
static time_t roots6_cdb_mtime = 0;

static void roots6_cdb_free(void)
{
  cdb_free(&roots6_cdb);
  if (!(roots6_cdb_fd < 0)) {
    close(roots6_cdb_fd);
    roots6_cdb_fd = -1;
  }
  roots6_cdb_mtime = 0;
  roots6_cdb_expiry = 0;
}

static void roots6_cdb_reload(void)
{
  struct stat st;

  roots6_cdb_free();

  roots6_cdb_fd = open_read(ROOTS_CDB_PATH);
  if (roots6_cdb_fd < 0) die_servers();

  cdb_init(&roots6_cdb, roots6_cdb_fd);

  if (fstat(roots6_cdb_fd, &st) < 0) die_servers();  /* ? */
  roots6_cdb_mtime = st.st_mtime;
}

static void roots6_cdb_check(void)
{
  time_t now;
  struct stat st;

  now = unix_now();
  if (now < roots6_cdb_expiry) return;  /* too soon */
  roots6_cdb_expiry = now + (time_t)5;

  if (stat(ROOTS_CDB_PATH, &st) < 0) die_servers();  /* file removed */
  if (st.st_mtime == roots6_cdb_mtime) return;  /* unchanged */

  roots6_cdb_reload();
}

static int roots6_search(const dns_domain *q)
{
  dns_domain dn;
  unsigned int len;
  int r;

  roots6_cdb_check();

  dn = *q;
  for (;;) {
    r = cdb_find(&roots6_cdb, dn.data, dn.len);
    if (r < 0) die_servers();
    if (r) return 1;
    len = dn.data[0];
    if (!len) return -1;  /* user misconfiguration */
    len++;  /* include 'label length' byte */
    dn.data += len;  /* simulate drop label, pt 1 */
    dn.len -= len;  /* simulate drop label, pt 2 */
  }
}

unsigned int roots6(const dns_domain *qname, ip6_vector *servers)
{
  static stralloc buf = STRALLOC;

  char *x;
  ip6_address ip;
  unsigned int i;
  unsigned int count;
  int r;

  roots6_cdb_check();

  r = cdb_find(&roots6_cdb, qname->data, qname->len);
  if (r < 0) die_servers();
  if (!r) return 0;

  if (!ip6_vector_erase(servers)) die_nomem();
  count = cdb_datalen(&roots6_cdb);
  count >>= 4;  /* div by 16 */

  if (!stralloc_erase(&buf)) die_nomem();
  if (cdb_read_stralloc(&roots6_cdb, &buf) < 0) die_servers();
  x = buf.s;
  for (i = 0; i < count; i++) {
    ip6_unpack(&ip, x);
    if (!ip6_vector_append(servers, &ip)) die_nomem();
    x += 16;
  }

  return 1;
}

unsigned int roots6_same(const dns_domain *q1, const dns_domain *q2)
{
  return roots6_search(q1) == roots6_search(q2);
}

void roots6_init(void)
{
  roots6_cdb_check();
}
