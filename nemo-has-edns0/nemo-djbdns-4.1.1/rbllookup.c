#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/open.h>
#include <nemo/env.h>
#include <nemo/cdb.h>
#include <nemo/error.h>
#include <nemo/unix.h>
#include <nemo/str.h>
#include <nemo/byte.h>

#include <sys/stat.h>

#include "dns.h"
#include "rbllookup.h"
#include "response.h"
#include "respond.h"
#include "die.h"
#include "data_cdb.h"

static char ip_str[IP6_FMT];

static stralloc data = STRALLOC;

unsigned int rbllookup_respond(const dns_domain *qname, unsigned int flag_a, unsigned int flag_txt)
{
  byte_t ip[4];
  int r;
  byte_t ch;

  r = cdb_find(&data_cdb, "", 0);
  if (r < 0) return 0;
  if (r && (cdb_datalen(&data_cdb) >= 4)) {
    if (!stralloc_erase(&data)) return 0;
    if (cdb_read_stralloc(&data_cdb, &data) < 0) return 0;
  }
  else {
    if (!stralloc_copyb(&data, "\177\000\000\002Listed $", 12)) return 0;
  }
  byte_copy(ip, 4, data.s);
  stralloc_remove(&data, 0, 4);

  if (stralloc_endb(&data, "$", 1)) {
    data.len--;
    if (!stralloc_catb(&data, ip_str, rbllookup_ip_fmt(ip_str))) return 0;
  }

  if (flag_a) {
    if (!response_rr_start(qname, dns_t_a, TTL_DNS)) return 0;
    if (!response_addbytes(ip, 4)) return 0;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
  }
  if (flag_txt) {
    if (!response_rr_start(qname, dns_t_txt, TTL_DNS)) return 0;
    if (data.len > MAX_DATA) {
      data.len = MAX_DATA;
    }
    ch = (byte_t)(data.len);
    if (!response_addbytes(&ch, 1)) return 0;
    if (!response_addbytes(data.s, data.len)) return 0;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
  }

  return 1;
}

int rbllookup_cdb_find(void *key, unsigned int len)
{
  return cdb_find(&data_cdb, key, len);
}

void initialize(void)
{
  const char *x;

  x = env_get("BASE");
  if (!x || !*x) die_env("BASE");
  if (!dns_domain_fromdot(&base, x, str_len(x))) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_parse("$BASE", x);
    die_internal();
  }
}
