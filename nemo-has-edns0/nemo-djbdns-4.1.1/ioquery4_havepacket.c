#include <nemo/stdint.h>
#include <nemo/alloc.h>
#include <nemo/uint16.h>
#include <nemo/uint32.h>
#include <nemo/byte.h>

#include "dnscache.h"
#include "log.h"
#include "cache.h"
#include "roots.h"
#include "dn_vector.h"
#include "die.h"
#include "safe.h"
#include "lame4_servers.h"

#include "client4.h"
#include "ioquery4.h"
#include "query4.h"
#include "tcpclient4.h"
#include "udpclient4.h"

#include "ioquery_havepacket.h"

/* #define DEBUG 1 */
#include "debug.h"

dns_domain owner_name = DNS_DOMAIN;
dns_domain referral = DNS_DOMAIN;

static const ip4_address *whichserver;
static uint32_t soa_ttl;

static dns_domain t1 = DNS_DOMAIN;
static dns_domain t2 = DNS_DOMAIN;
static dns_domain t3 = DNS_DOMAIN;


/* 0: data error, 1: OK */
static unsigned int do_all_answers(const byte_t *buf, unsigned int len, dns_domain *control, unsigned int num_total, unsigned int pos_authority)
{
  byte_t header[12];
  byte_t misc[20];
  dns_type type;
  ip4_address ip4;
  ip6_address ip6;
  unsigned int i;
  unsigned int j;
  unsigned int pos;
  unsigned int flag_authority;
  uint32_t ttl;
  uint16_t data_len;

  i = 0;
  while (i < num_total) {
    pos = safe_packet_getname(buf, len, records[i], &t1);
    if (!pos) return 0;
    dns_domain_lower(&t1);
    pos = dns_packet_copy(buf, len, pos, header, 10);
    if (!pos) return 0;

    if (dns_class_diffb(dns_c_in, header + 2)) {
      i++;
      continue;
    }

    dns_type_unpack(&type, header);
    ttl = ioquery_ttl_get(header + 4);

    for (j = i + 1; j < num_total; ++j) {
      pos = safe_packet_getname(buf, len, records[j], &t2);
      if (!pos) return 0;
      dns_domain_lower(&t2);
      pos = dns_packet_copy(buf, len, pos, header, 10);
      if (!pos) return 0;
      if (!dns_domain_equal(&t1, &t2)) break;
      if (dns_type_diffb(&type, header)) break;
      if (dns_class_diffb(dns_c_in, header + 2)) break;
    }

    if (!dns_domain_suffix(&t1, control)) {  /* reject poison */
      i = j;
      continue;
    }

    if (!roots4_same(&t1, control)) {
      i = j;
      continue;
    }

    switch (dns_type_get(&type)) {
      case DNS_T_ANY:
        break;

      case DNS_T_AXFR:
        break;

      case DNS_T_IXFR:
        break;

      case DNS_T_OPT:
        break;

      case DNS_T_SOA:
        flag_authority = 0;
        ioquery_save_start();
        while (i < j) {
          pos = dns_packet_skipname(buf, len, records[i]);
          if (!pos) return 0;
          pos = safe_packet_getname(buf, len, pos + 10, &t2);
          if (!pos) return 0;
          dns_domain_lower(&t2);
          pos = safe_packet_getname(buf, len, pos, &t3);
          if (!pos) return 0;
          dns_domain_lower(&t3);
          pos = dns_packet_copy(buf, len, pos, misc, 20);
          if (!pos) return 0;
          if (records[i] >= pos_authority) {
            log4_rr_soa(whichserver, &t1, &t2, &t3, misc, ttl);
            ioquery_save_data(misc, 20);
            ioquery_save_data(t2.data, t2.len);
            ioquery_save_data(t3.data, t3.len);
            flag_authority = 1;
          }
          i++;
        }
        if (flag_authority) {
          ioquery_save_finish(dns_t_soa, &t1, ttl);
        }
        break;

      case DNS_T_CNAME:
        pos = dns_packet_skipname(buf, len, records[j - 1]);
        if (!pos) return 0;
        pos = safe_packet_getname(buf, len, pos + 10, &t2);
        if (!pos) return 0;
        dns_domain_lower(&t2);
        log4_rr_cname(whichserver, &t1, &t2, ttl);
        cache_generic(dns_t_cname, &t1, t2.data, t2.len, ttl);
        break;

      case DNS_T_PTR:
        ioquery_save_start();
        while (i < j) {
          pos = dns_packet_skipname(buf, len, records[i]);
          if (!pos) return 0;
          pos = safe_packet_getname(buf, len, pos + 10, &t2);
          if (!pos) return 0;
          dns_domain_lower(&t2);
          log4_rr_ptr(whichserver, &t1, &t2, ttl);
          ioquery_save_data(t2.data, t2.len);
          i++;
        }
        ioquery_save_finish(dns_t_ptr, &t1, ttl);
        break;

      case DNS_T_NS:
        ioquery_save_start();
        while (i < j) {
          pos = dns_packet_skipname(buf, len, records[i]);
          if (!pos) return 0;
          pos = safe_packet_getname(buf, len, pos + 10, &t2);
          if (!pos) return 0;
          dns_domain_lower(&t2);
          log4_rr_ns(whichserver, &t1, &t2, ttl);
          ioquery_save_data(t2.data, t2.len);
          i++;
        }
        ioquery_save_finish(dns_t_ns, &t1, ttl);
        break;

      case DNS_T_MX:
        ioquery_save_start();
        while (i < j) {
          pos = dns_packet_skipname(buf, len, records[i]);
          if (!pos) return 0;
          pos = dns_packet_copy(buf, len, pos + 10, misc, 2);
          if (!pos) return 0;
          pos = safe_packet_getname(buf, len, pos, &t2);
          dns_domain_lower(&t2);
          if (!pos) return 0;
          log4_rr_mx(whichserver, &t1, &t2, misc, ttl);
          ioquery_save_data(misc, 2);
          ioquery_save_data(t2.data, t2.len);
          i++;
        }
        ioquery_save_finish(dns_t_mx, &t1, ttl);
        break;

      case DNS_T_A:
        ioquery_save_start();
        while (i < j) {
          pos = dns_packet_skipname(buf, len, records[i]);
          if (!pos) return 0;
          pos = dns_packet_copy(buf, len, pos, header, 10);
          if (!pos) return 0;
          uint16_unpack_big(&data_len, header + 8);
          if (data_len == 4) {
            pos = dns_packet_copy(buf, len, pos, misc, 4);
            if (!pos) return 0;
            ip4_unpack(&ip4, misc);
            if (!ignore_ip4(&ip4)) {
              ioquery_save_data(misc, 4);
              log4_rr_a(whichserver, &t1, &ip4, ttl);
            }
          }
          i++;
        }
        ioquery_save_finish(dns_t_a, &t1, ttl);
        break;

      case DNS_T_AAAA:
        ioquery_save_start();
        while (i < j) {
          pos = dns_packet_skipname(buf, len, records[i]);
          if (!pos) return 0;
          pos = dns_packet_copy(buf, len, pos, header, 10);
          if (!pos) return 0;
          uint16_unpack_big(&data_len, header + 8);
          if (data_len == 16) {
            pos = dns_packet_copy(buf, len, pos, misc, 16);
            if (!pos) return 0;
            ip6_unpack(&ip6, misc);
            if (!ignore_ip6(&ip6)) {
	      ioquery_save_data(misc, 16);
	      log4_rr_aaaa(whichserver, &t1, &ip6, ttl);
            }
          }
          i++;
        }
        ioquery_save_finish(dns_t_aaaa, &t1, ttl);
        break;

      default:
        ioquery_save_start();
        while (i < j) {
          pos = dns_packet_skipname(buf, len, records[i]);
          if (!pos) return 0;
          pos = dns_packet_copy(buf, len, pos, header, 10);
          if (!pos) return 0;
          uint16_unpack_big(&data_len, header + 8);
          if (data_len > len - pos) return 0;
          ioquery_save_data(header + 8, 2);
          ioquery_save_data(buf + pos, data_len);
          log4_rr(whichserver, &t1, &type, buf + pos, data_len, ttl);
          i++;
        }
        ioquery_save_finish(&type, &t1, ttl);
        break;
    } /* switch */
    i = j;
  }

  return 1;
}

static dns_rcode_t do_havepacket(ioquery *x)
{
  byte_t header[12];
  byte_t *buf;
  unsigned int len;
  dns_type *type;
  dns_domain *name;
  dns_domain *control;
  unsigned int qtype;
  unsigned int rcode;
  uint16_t num_answers;
  uint16_t num_authority;
  uint16_t num_additional;
  unsigned int pos_answers;
  unsigned int pos_authority;
  unsigned int pos;
  unsigned int flag_referral;
  unsigned int flag_soa;
  unsigned int flag_found;

  buf = x->dt.packet;
  len = x->dt.packetlen;
  control = &x->control;
  name = &x->name;
  type = &x->type;
  qtype = dns_type_get(type);
  whichserver = &x->dt.servers->va[x->dt.curserver];
  soa_ttl = 0;

  pos = dns_packet_copy(buf, len, 0, header, 12);
  if (!pos) return DNS_RCODE_SERVFAIL;
  pos = dns_packet_skipname(buf, len, pos);
  if (!pos) return DNS_RCODE_SERVFAIL;
  pos += 4;
  pos_answers = pos;

  uint16_unpack_big(&num_answers, header + 6);
  uint16_unpack_big(&num_authority, header + 8);
  uint16_unpack_big(&num_additional, header + 10);
  debug_putuint("num_answers", num_answers);
  debug_putuint("num_authority", num_authority);
  debug_putuint("num_additional", num_additional);

  rcode = header[3] & 15;

  if (rcode == DNS_RCODE_SERVFAIL) return DNS_RCODE_SERVFAIL;  /* assume returned info meaningless */

  if ((rcode != DNS_RCODE_NOERROR) && (rcode != DNS_RCODE_NXDOMAIN)) return rcode;  /* impossible, see irrelevant() */

  if (!dns_domain_copy(&owner_name, name)) die_nomem();
  if (!ioquery_scan_records(buf, len, pos_answers, qtype, num_answers, num_authority, num_additional, &flag_found, &flag_soa, &flag_referral, &soa_ttl, &pos_authority)) return DNS_RCODE_SERVFAIL;

  if (ioquery_opt_count() > 1) return DNS_RCODE_FORMERR;

  debug_putuint("rr_count", rr_count);
/*
  NB: some servers return RRs + NXDOMAIN
*/
  debug_putuint("flag_found", flag_found);
  debug_putuint("flag_soa", flag_soa);
  debug_putuint("flag_referral", flag_referral);

  if (!rr_count) return DNS_RCODE_NXDOMAIN;  /* safety */

  ioquery_sort_records(buf, len, rr_count);

  if (!do_all_answers(buf, len, control, rr_count, pos_authority)) return DNS_RCODE_SERVFAIL;

  if (flag_found) return DNS_RCODE_NOERROR;
/*
  !flag_found
*/
  debug_puttype("query type", type);
  debug_putdomain("query domain", name);
  debug_putdomain("control domain", control);
  debug_putdomain("referral domain", &referral);

  if ((DNS_T_ANY == qtype) || (DNS_T_AXFR == qtype) || (DNS_T_IXFR == qtype) || (DNS_T_OPT == qtype)) return DNS_RCODE_NOTIMP;
/*
  We check for a lame server _after_ we have cached any records that it
  might have returned to us.  This copes better with the incorrect behaviour
  of one content DNS server software that doesn't return complete CNAME chains
  but instead returns only the first link in a chain followed by a lame
  delegation to the same server.
  Also: We check for a lame server _after_ following the CNAME chain.  The
  delegation in a referral answer applies to the _end_ of the chain, not
  to the beginning.
*/
  if (flag_referral && !flag_soa) {
    if (dns_domain_equal(&referral, control) || !dns_domain_suffix(&referral, control)) {
      log4_lame(whichserver, control, &referral);
      lame4_servers_add(control, whichserver, soa_ttl);
      ip4_vector_remove(x->dt.servers, x->dt.curserver, 1);
      return DNS_RCODE_NOERROR;
    }
  }
/*
  mark empty RR sets as NXDOMAIN in baliwick
*/
/*  if (flag_soa && !flag_referral) return DNS_RCODE_NXDOMAIN;  */
  if (flag_soa) return DNS_RCODE_NXDOMAIN;

  return DNS_RCODE_NOERROR;
}

void ioquery_havepacket(ioquery *x)
{
  dns_rcode_t rcode;

  rcode = do_havepacket(x);

  if (rcode == DNS_RCODE_NXDOMAIN) {
    cache_mark(&x->type, &x->name, CACHE_NXDOMAIN, soa_ttl);
  }
  else if (rcode == DNS_RCODE_SERVFAIL) {
    cache_mark(&x->type, &x->name, CACHE_SERVFAIL, soa_ttl);
  }

  if (rcode != DNS_RCODE_NOERROR) {
    log4_rcode(rcode, whichserver, &x->name, &x->type, soa_ttl);
  }

  ioquery_signal_clients(x);
  ioquery_free(x);
}
