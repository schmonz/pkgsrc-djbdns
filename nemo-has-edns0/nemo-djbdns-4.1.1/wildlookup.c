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
#include "wildlookup.h"
#include "die.h"
#include "data_cdb.h"

static ip4_address ip4_default = IP4_ADDRESS;
static ip6_address ip6_default = IP6_ADDRESS;

static ip4_address ip4_result = IP4_ADDRESS;
static ip6_address ip6_result = IP6_ADDRESS;

static unsigned int flag_a_default = 0;
static unsigned int flag_aaaa_default = 0;

static int search(const dns_domain *qname)
{
  static dns_domain d = DNS_DOMAIN;
  static byte_t key[257];
  static byte_t data[20];

  unsigned int dlen;
  uint32_t klen;
  int r;

  if (!dns_domain_copy(&d, qname)) return -1;
  dns_domain_pack(&d, key);
  klen = dns_domain_length(&d);

  for (;;) {
    r = cdb_find(&data_cdb, key, klen);
    if (r < 0) return -1;
    if (r) break;
    if (!dns_domain_drop1label(&d)) return 0;
    if (dns_domain_labelcount(&d) < 2) return 0;
    dns_domain_pack(&d, key);
    klen = dns_domain_length(&d);
  }

  ip4_zero(&ip4_result);
  ip6_zero(&ip6_result);

  dlen = cdb_datalen(&data_cdb);

  if (!dlen) return 1;  /* old format */
  if (dlen != sizeof data) return -1;  /* corrupt CDB */

  byte_zero(data, sizeof data);
  if (cdb_read(&data_cdb, data, dlen, cdb_datapos(&data_cdb)) < 0) return -1;

  ip4_unpack(&ip4_result, data);
  ip6_unpack(&ip6_result, data + 4);

  return 1;
}

unsigned int wildlookup_doit(const dns_domain *qname, const dns_type *qtype)
{
  unsigned int type;
  unsigned int flag_any;
  int r;

  type = dns_type_get(qtype);
  flag_any = type == DNS_T_ANY;
  if (type != DNS_T_A && type != DNS_T_AAAA && !flag_any) {
    response[2] &= (byte_t)(~4);
    response_refused();
    return 3;  /* REJECTED */
  }

  r = search(qname);
  if (r < 0) return 0;
  if (!r) {
    response_nxdomain();
    return 2;
  }

  if (type == DNS_T_A || flag_any) {
    if (ip4_diff(&ip4_result, null_ip4)) {
      if (!response_rr_start(qname, dns_t_a, TTL_DNS)) return 0;
      if (!response_addip4(&ip4_result)) return 0;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
    else if (flag_a_default) {
      if (!response_rr_start(qname, dns_t_a, TTL_DNS)) return 0;
      if (!response_addip4(&ip4_default)) return 0;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
  }

  if (type == DNS_T_AAAA || flag_any) {
    if (ip6_diff(&ip6_result, 	null_ip6)) {
      if (!response_rr_start(qname, dns_t_aaaa, TTL_DNS)) return 0;
      if (!response_addip6(&ip6_result)) return 0;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
    else if (flag_aaaa_default) {
      if (!response_rr_start(qname, dns_t_aaaa, TTL_DNS)) return 0;
      if (!response_addip6(&ip6_default)) return 0;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
  }

  return 1;
}

void initialize(void)
{
  const char *x;
  unsigned int i;

  x = env_get("A");
  if (x && *x) {
    i = ip4_scan(&ip4_default, x);
    if (!i || x[i]) die_parse("IPv4 address", x);
    flag_a_default = 1;
  }

  x = env_get("AAAA");
  if (x && *x) {
    i = ip6_scan(&ip6_default, x);
    if (!i || x[i]) die_parse("IPv6 address", x);
    flag_aaaa_default = 1;
  }
}
