#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/cdb.h>
#include <nemo/byte.h>

#include "dns.h"
#include "tdlookup.h"
#include "data_cdb.h"

unsigned int tdlookup_loc_setup(void *key, unsigned int keylen)
{
  register unsigned int i;
  register int r;

  byte_zero(client_loc, LOC_LEN);
  i = keylen;
  do {
    r = cdb_find(&data_cdb, key, i);
    if (r < 0) return 0;
    if (r) break;
    i--;
  } while (i >= KEY_PREFIX_LEN);
  if (r && (cdb_datalen(&data_cdb) == LOC_LEN)) {
    if (cdb_read(&data_cdb, client_loc, LOC_LEN, cdb_datapos(&data_cdb)) < 0) return 0;
  }
  return 1;
}
