#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/open.h>
#include <nemo/env.h>
#include <nemo/cdb.h>
#include <nemo/error.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>
#include <nemo/unix.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/macro_unused.h>

#include "rbldns6.h"
#include "dns.h"
#include "dd.h"
#include "response.h"
#include "respond.h"
#include "rbllookup.h"
#include "data_cdb.h"

dns_domain base = DNS_DOMAIN;

static ip6_address ip6;

static byte_t key[17];

unsigned int rbllookup_ip_fmt(char *d)
{
  return ip6_fmt(&ip6, d);
}

/*
  derived from ip6_mask_0() - optimised for RBLDNS6_MAX_BYTES
*/
static void ip_mask_0(ip6_address *ip, unsigned int mask_depth)
{
  unsigned int first_byte;
  unsigned int i;
  byte_t ch;

  first_byte = mask_depth >> 3;  /* div by 8 (bits/byte) */
  if (mask_depth & 7) {
    first_byte++;  /* skip part byte */
  }
  for (i = first_byte; i < RBLDNS6_MAX_BYTES; i++) {
    ip->d[i] = '\0';
  }

  i = 8 - (mask_depth & 7);  /* shift count (from mod 8) */
  if (i == 8) return;        /* byte boundary */

  first_byte--;  /* revert to part byte */
  ch = (byte_t)(ip->d[first_byte] >> i);
  ip->d[first_byte] = (byte_t)(ch << i);
}


static unsigned int rbllookup_doit(const dns_domain *qname, const dns_type *qtype)
{
  unsigned int flag_a;
  unsigned int flag_txt;
  unsigned int i;
  int r;

  flag_a = dns_type_equal(qtype, dns_t_a);
  flag_txt = dns_type_equal(qtype, dns_t_txt);
  if (dns_type_equal(qtype, dns_t_any)) {
    flag_a = flag_txt = 1;
  }
  if (!flag_a && !flag_txt) goto REFUSE;

  if (dd6(qname, &base, &ip6) != 32) goto REFUSE;
  ip6_reverse(&ip6);
/*
  limit to searching [ ip/RBLDNS6_MAX_MASK .. ip/8 ]
*/
  for (i = RBLDNS6_MAX_MASK; i >= 8; --i) {
    ip_mask_0(&ip6, i);
    ip6_pack(&ip6, key);
    key[RBLDNS6_MAX_BYTES] = (byte_t)(i);
    r = rbllookup_cdb_find(key, RBLDNS6_MAX_BYTES + 1);
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

unsigned int respond6(const dns_domain *qname, const dns_type *qtype, const ip6_address *ip __UNUSED__, unsigned int udp_size __UNUSED__, unsigned int flag_edns0 __UNUSED__)
{
  data_cdb_setup();
  return rbllookup_doit(qname, qtype);
}
