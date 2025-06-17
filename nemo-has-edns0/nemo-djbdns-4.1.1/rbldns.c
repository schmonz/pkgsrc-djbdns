#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/str.h>
#include <nemo/open.h>
#include <nemo/env.h>
#include <nemo/cdb.h>
#include <nemo/error.h>
#include <nemo/ip4.h>
#include <nemo/uint32.h>
#include <nemo/unix.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "dd.h"
#include "rbllookup.h"
#include "respond.h"
#include "response.h"
#include "data_cdb.h"

dns_domain base = DNS_DOMAIN;

static ip4_address ip4;

static byte_t key[5];

unsigned int rbllookup_ip_fmt(char *data)
{
  return ip4_fmt(&ip4, data);
}

static unsigned int rbllookup_doit(const dns_domain *qname, const dns_type *qtype)
{
  unsigned int flag_a;
  unsigned int flag_txt;
  unsigned int i;
  uint32_t ipnum;
  int r;

  flag_a = dns_type_equal(qtype, dns_t_a);
  flag_txt = dns_type_equal(qtype, dns_t_txt);
  if (dns_type_equal(qtype, dns_t_any)) {
    flag_a = flag_txt = 1;
  }
  if (!flag_a && !flag_txt) goto REFUSE;

  if (dd4(qname, &base, &ip4) != 4) goto REFUSE;
  ip4_reverse(&ip4);
  uint32_unpack_big(&ipnum, ip4.d);

  for (i = 0; i <= 24; ++i) {
    ipnum >>= i;
    ipnum <<= i;
    uint32_pack_big(ipnum, key);
    key[4] = (byte_t)(32 - i);
    r = rbllookup_cdb_find(key, 5);
    if (r < 0) return 0;
    if (r) break;
  }
  if (!r) {
    response_nxdomain();
    return 2;
  }

  return rbllookup_respond(qname, flag_a, flag_txt);

REFUSE:
  response[2] &= (byte_t)(~4);
  response_refused();
  return 3;  /* REJECTED */
}

unsigned int respond4(const dns_domain *qname, const dns_type *qtype, const ip4_address *ip __UNUSED__, unsigned int udp_size __UNUSED__, unsigned int flag_edns0 __UNUSED__)
{
  data_cdb_setup();
  return rbllookup_doit(qname, qtype);
}
