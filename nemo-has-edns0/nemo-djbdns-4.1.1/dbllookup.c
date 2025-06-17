#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/open.h>
#include <nemo/env.h>
#include <nemo/cdb.h>
#include <nemo/ip4.h>
#include <nemo/uint32.h>
#include <nemo/unix.h>
#include <nemo/str.h>
#include <nemo/error.h>
#include <nemo/byte.h>

#include "dns.h"
#include "response.h"
#include "respond.h"
#include "dbllookup.h"
#include "data_cdb.h"
#include "die.h"

static dns_domain wild = DNS_DOMAIN;
static dns_domain base = DNS_DOMAIN;

static stralloc data = STRALLOC;
static stralloc qdomain = STRALLOC;

/*
  exact match on first loop,
  wild card only on subsequent loops
*/
static int search(const dns_domain *qname, unsigned int pos)
{
  static dns_domain d = DNS_DOMAIN;
  static byte_t key[257];

  uint32_t klen;
  int r;
/*
  trim base, set up key
*/
  dns_domain_pack(qname, key);
  key[pos] = '\0';
  klen = pos + 1;
/*
  save original domain
*/
  if (!dns_domain_unpack(&d, key)) return -1;
  if (!stralloc_erase(&qdomain)) return -1;
  if (!dns_domain_todot_cat(&d, &qdomain)) return -1;
/*
  wildcard prefix search loop
*/
  for (;;) {
    r = cdb_find(&data_cdb, key, klen);
    if (r < 0) return -1;
    if (r) break;
    if (!dns_domain_drop1label(&d)) return 0;
    if (!dns_domain_labelcount(&d)) return 0;
    if (!dns_domain_fromdot(&wild, "*", 1)) return 0;
    if (!dns_domain_cat(&wild, &d)) return 0;
    dns_domain_pack(&wild, key);
    klen = dns_domain_length(&wild);
  }
  return 1;
}

unsigned int dbllookup_doit(const dns_domain *qname, const dns_type *qtype)
{
  byte_t ip[4];
  unsigned int flag_a;
  unsigned int flag_txt;
  unsigned int i;
  int r;
  byte_t ch;

  flag_a = dns_type_equal(qtype, dns_t_a);
  flag_txt = dns_type_equal(qtype, dns_t_txt);
  if (dns_type_equal(qtype, dns_t_any)) {
    flag_a = flag_txt = 1;
  }
  if (!flag_a && !flag_txt) goto REFUSE;
/*
  test for base (suffix)
*/
  i = dns_domain_suffixpos(qname, &base);
  if (!i) goto REFUSE;
/*
  search
*/
  r = search(qname, i);
  if (r < 0) return 0;
  if (!r) {
    response_nxdomain();
    return 2;
  }
/*
  find response data
*/
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
    if (!stralloc_cat(&data, &qdomain)) return 0;
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

REFUSE:
  response[2] &= (byte_t)(~4);
  response_refused();
  return 3;  /* REJECTED */
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
