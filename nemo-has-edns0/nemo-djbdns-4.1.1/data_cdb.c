#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/unix.h>
#include <nemo/cdb.h>
#include <nemo/open.h>

#include <sys/stat.h>

#include "data_cdb.h"
#include "die.h"

struct cdb data_cdb = CDB;

static const char DATA_CDB_PATH[] = "data.cdb";

static int data_cdb_fd = -1;

static time_t data_cdb_expiry = 0;
static time_t data_cdb_mtime = 0;

static void data_cdb_free(void)
{
  cdb_free(&data_cdb);
  if (!(data_cdb_fd < 0)) {
    close(data_cdb_fd);
    data_cdb_fd = -1;
  }
  data_cdb_mtime = 0;
  data_cdb_expiry = 0;
}

static void data_cdb_reload(void)
{
  struct stat st;

  data_cdb_free();
  data_cdb_fd = open_read(DATA_CDB_PATH);
  if (data_cdb_fd < 0) die_read(DATA_CDB_PATH);

  cdb_init(&data_cdb, data_cdb_fd);

  if (fstat(data_cdb_fd, &st) < 0) die_read(DATA_CDB_PATH);  /* file removed */
  data_cdb_mtime = st.st_mtime;
}

void data_cdb_setup(void)
{
  time_t now;
  struct stat st;

  now = unix_now();
  if (now < data_cdb_expiry) return;  /* too soon */
  data_cdb_expiry = now + (time_t)5;

  if (stat(DATA_CDB_PATH, &st) < 0) die_read(DATA_CDB_PATH);  /* file removed */
  if (st.st_mtime == data_cdb_mtime) return;  /* unchanged */

  data_cdb_reload();
}
