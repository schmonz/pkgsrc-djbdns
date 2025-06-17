#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/tai.h>
#include <nemo/cdb.h>
#include <nemo/byte.h>
#include <nemo/unix.h>
#include <nemo/uint16.h>
#include <nemo/uint32.h>

#include "dns.h"
#include "response.h"
#include "respond.h"
#include "tdlookup.h"
#include "die.h"
#include "safe.h"
#include "data_cdb.h"

#define TTL_LEN 4
#define TTD_LEN 8

byte_t client_loc[LOC_LEN];

static unsigned int want_other(const dns_domain *owner, const dns_type *type)
{
  static dns_domain d = DNS_DOMAIN;
  unsigned int pos;
  byte_t x[10];
  uint16_t datalen;

  pos = dns_packet_skipname(response, response_len, 12);
  if (!pos) return 0;
  pos += 4;

  while (pos < response_len) {
    pos = safe_packet_getname(response, response_len, pos, &d);
    if (!pos) return 0;
    pos = dns_packet_copy(response, response_len, pos, x, 10);
    if (!pos) return 0;
    if (dns_domain_equal(&d, owner)) {
      if (dns_type_equalb(type, x)) {
        return 0;
      }
    }
    uint16_unpack_big(&datalen, x + 8);
    pos += datalen;
  }
  return 1;
}

static dns_domain d1 = DNS_DOMAIN;

static byte_t data[32767];
static uint32_t dlen;
static unsigned int dpos;

static uint32_t ttl;

static struct tai tnow;

static int find(dns_domain *d, unsigned int flag_wild, dns_type *cur_type)
{
  struct tai cut_off;
  byte_t ttd_buf[TTD_LEN];
  byte_t ttl_buf[TTL_LEN];
  byte_t record_loc[LOC_LEN];
  byte_t misc[2];
  uint64_t new_ttl;
  int r;
  byte_t ch;

  for (;;) {
    r = cdb_findnext(&data_cdb, d->data, d->len);
    if (r <= 0) return r;
    dlen = cdb_datalen(&data_cdb);
    if (dlen > sizeof data) return -1;
    if (cdb_read(&data_cdb, data, dlen, cdb_datapos(&data_cdb)) < 0) return -1;
    dpos = dns_packet_copy(data, dlen, 0, misc, 2);
    if (!dpos) return -1;
    dns_type_unpack(cur_type, misc);
    dpos = dns_packet_copy(data, dlen, dpos, &ch, 1);
    if (!dpos) return -1;
    if ((ch == '=' + 1) || (ch == '*' + 1)) {  /*  '>'  '+'  */
      --ch;
      dpos = dns_packet_copy(data, dlen, dpos, record_loc, LOC_LEN);
      if (!dpos) return -1;
      if (byte_diff(record_loc, LOC_LEN, client_loc)) continue;
    }
    if (flag_wild != (ch == '*')) continue;
    dpos = dns_packet_copy(data, dlen, dpos, ttl_buf, TTL_LEN);
    if (!dpos) return -1;
    uint32_unpack_big(&ttl, ttl_buf);
    dpos = dns_packet_copy(data, dlen, dpos, ttd_buf, TTD_LEN);
    if (!dpos) return -1;
    if (byte_diff(ttd_buf, TTD_LEN, "\0\0\0\0\0\0\0\0")) {
      tai_unpack(&cut_off, ttd_buf);
      if (ttl == 0) {
        if (tai_less(&cut_off, &tnow)) continue;
        tai_sub(&cut_off, &cut_off, &tnow);
        new_ttl = tai_seconds(&cut_off);
        if (new_ttl <= 2) {
          new_ttl = 2;
        }
        else if (new_ttl >= 3600) {
          new_ttl = 3600;
        }
        ttl = (uint32_t)new_ttl;
      }
      else {
        if (!tai_less(&cut_off, &tnow)) continue;
      }
    }
    return 1;
  }
}

static unsigned int do_bytes(unsigned int len)
{
  byte_t buf[20];
  if (len > 20) return 0;
  dpos = dns_packet_copy(data, dlen, dpos, buf, len);
  if (!dpos) return 0;
  return response_addbytes(buf, len);
}

static unsigned int do_name(void)
{
  dpos = safe_packet_getname(data, dlen, dpos, &d1);
  if (!dpos) return 0;
  return response_addname(&d1);
}

#define MAX_ADDRESS 8

unsigned int tdlookup_doit(const dns_domain *qname, const dns_type *qtype, unsigned int udp_size, unsigned int flag_edns0)
{
  static dns_domain name = DNS_DOMAIN;
  static dns_domain control = DNS_DOMAIN;
  static dns_domain wild = DNS_DOMAIN;

  dns_type cur_find_type;

  ip4_address addr4[MAX_ADDRESS];
  ip6_address addr6[MAX_ADDRESS];
  unsigned int addr4_num;
  unsigned int addr6_num;
  uint32_t addr4_ttl;
  uint32_t addr6_ttl;

  unsigned int i;
  unsigned int bpos;
  unsigned int pos_answer;
  unsigned int pos_authority;
  unsigned int pos_additional;
  unsigned int flag_found;
  unsigned int flag_gave_soa;
  unsigned int flag_control_ns;
  unsigned int flag_control_authoritative;
  byte_t x[20];
  uint16_t u16;
  unsigned int loop;
  unsigned int result;
  int r;

  loop = 0;
  result = 1; /* normal result */
  flag_gave_soa = flag_found = 0;

  if (!dns_domain_copy(&name, qname)) die_nomem();

  pos_answer = response_len;

RESTART:
  if (++loop == 100) return 0;

  if (!dns_domain_copy(&control, &name)) die_nomem();

  for (;;) {
    flag_control_ns = flag_control_authoritative = 0;
    cdb_findstart(&data_cdb);
    while ((r = find(&control, 0, &cur_find_type))) {
      if (r < 0) return 0;
      if (dns_type_equal(&cur_find_type, dns_t_soa)) {
        flag_control_authoritative = 1;
      }
      else if (dns_type_equal(&cur_find_type, dns_t_ns)) {
        flag_control_ns = 1;
      }
    }
    if (flag_control_ns) break;
    if (!dns_domain_labellength(&control)) {  /* qname is not within our bailiwick */
      response_nxdomain();
      return 3;  /* REJECTED - The administrator has issued contradictory instructions */
    }
    dns_domain_drop1label(&control);
  }

  if (!flag_control_authoritative) {  /* referral */
    response[2] &= (byte_t)(~4);  /* remove AA */
    goto AUTHORITY;  /* qname is in a child zone */
  }

  if (!dns_domain_copy(&wild, &name)) die_nomem();

  for (;;) {
    addr6_num = addr4_num = 0;
    addr6_ttl = addr4_ttl = 0;
    cdb_findstart(&data_cdb);
    while ((r = find(&wild, !dns_domain_equal(&wild, &name), &cur_find_type))) {
      if (r < 0) return 0;
      if (flag_gave_soa && dns_type_equal(&cur_find_type, dns_t_soa)) continue;
      if (dns_type_diff(&cur_find_type, qtype) && dns_type_diff(qtype, dns_t_any) && dns_type_diff(&cur_find_type, dns_t_cname)) continue;
      flag_found = 1;

      if (dns_type_equal(&cur_find_type, dns_t_a) && (dlen - dpos == 4)) {
        addr4_ttl = ttl;
        i = dns_random(addr4_num + 1);
        if (i < MAX_ADDRESS) {
          if ((i < addr4_num) && (addr4_num < MAX_ADDRESS)) {
            ip4_copy(&addr4[addr4_num], &addr4[i]);
          }
          ip4_unpack(&addr4[i], data + dpos);
        }
        if (addr4_num < 1000000) {
          ++addr4_num;
        }
        continue;
      }

      if (dns_type_equal(&cur_find_type, dns_t_aaaa) && (dlen - dpos == 16)) {
        addr6_ttl = ttl;
        i = dns_random(addr6_num + 1);
        if (i < MAX_ADDRESS) {
          if ((i < addr6_num) && (addr6_num < MAX_ADDRESS)) {
            ip6_copy(&addr6[addr6_num], &addr6[i]);
          }
          ip6_unpack(&addr6[i], data + dpos);
        }
        if (addr6_num < 1000000) {
          ++addr6_num;
        }
        continue;
      }

      if (!response_rr_start(&name, &cur_find_type, ttl)) return 0;

      if (dns_type_equal(&cur_find_type, dns_t_ns) || dns_type_equal(&cur_find_type, dns_t_ptr)) {
	if (!do_name()) return 0;
      }
      else if (dns_type_equal(&cur_find_type, dns_t_cname)) {
        if (!do_name()) return 0;
        if (dns_type_equal(&cur_find_type, qtype)) {
	  response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
	  if (!dns_domain_copy(&name, &d1)) die_nomem();
	  goto RESTART;
	}
      }
      else if (dns_type_equal(&cur_find_type, dns_t_mx)) {
        if (!do_bytes(2)) return 0;
        if (!do_name()) return 0;
      }
      else if (dns_type_equal(&cur_find_type, dns_t_soa)) {
        if (!do_name()) return 0;
        if (!do_name()) return 0;
        if (!do_bytes(20)) return 0;
        flag_gave_soa = 1;
      }
      else {
        if (!response_addbytes(data + dpos, dlen - dpos)) return 0;
      }
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
    for (i = 0; i < addr4_num; ++i) {
      if (i < MAX_ADDRESS) {
        if (!response_rr_start(&name, dns_t_a, addr4_ttl)) return 0;
        if (!response_addip4(&addr4[i])) return 0;
        response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
      }
    }
    for (i = 0; i < addr6_num; ++i) {
      if (i < MAX_ADDRESS) {
        if (!response_rr_start(&name, dns_t_aaaa, addr6_ttl)) return 0;
        if (!response_addip6(&addr6[i])) return 0;
        response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
      }
    }

    if (flag_found) break;
    if (dns_domain_equal(&wild, &control)) break;
    if (!dns_domain_labellength(&wild)) break;  /* impossible */
    dns_domain_drop1label(&wild);
  }

  if (!flag_found) {
    /* response_nxdomain(); */
    result = 2;  /* -ve result */
    if (!dns_domain_equal(&control, &name)) {
      response[2] &= (byte_t)(~4);  /* remove AA */
    }
  }

AUTHORITY:
  pos_authority = response_len;

  if (pos_authority == pos_answer) {
    if (!dns_domain_equal(&control, &name)) {
      response[2] &= (byte_t)(~4);
      if (flag_control_authoritative) {
	cdb_findstart(&data_cdb);
	while ((r = find(&control, 0, &cur_find_type))) {
	  if (r < 0) return 0;
	  if (dns_type_equal(&cur_find_type, dns_t_soa)) {
	    if (!response_rr_start(&control, dns_t_soa, ttl)) return 0;
	    if (!do_name()) return 0;
	    if (!do_name()) return 0;
	    if (!do_bytes(20)) return 0;
	    response_rr_finish(DNS_HEADER_AUTHORITY_COUNT_OFFSET);
	    break;
	  }
	}
      }
      cdb_findstart(&data_cdb);
      while ((r = find(&control, 0, &cur_find_type))) {
	if (r < 0) return 0;
	if (dns_type_equal(&cur_find_type, dns_t_ns)) {
	  if (!response_rr_start(&control, dns_t_ns, ttl)) return 0;
	  if (!do_name()) return 0;
	  response_rr_finish(DNS_HEADER_AUTHORITY_COUNT_OFFSET);
	}
      }
    }
  }

/*
  else {
    if (want_other(&control, dns_t_ns)) {
      cdb_findstart(&data_cdb);
      while ((r = find(&control, 0, &cur_find_type))) {
	if (r < 0) return 0;
	if (dns_type_equal(&cur_find_type, dns_t_ns)) {
	  if (!response_rr_start(&control, dns_t_ns, ttl)) return 0;
	  if (!do_name()) return 0;
	  response_rr_finish(DNS_HEADER_AUTHORITY_COUNT_OFFSET);
	}
      }
    }
  }
*/
/*
  if (flag_control_authoritative && (pos_authority == pos_answer)) {
    cdb_findstart(&data_cdb);
    while ((r = find(&control, 0, &cur_find_type))) {
      if (r < 0) return 0;
      if (dns_type_equal(&cur_find_type, dns_t_soa)) {
	if (!response_rr_start(&control, dns_t_soa, ttl)) return 0;
	if (!do_name()) return 0;
	if (!do_name()) return 0;
	if (!do_bytes(20)) return 0;
	response_rr_finish(DNS_HEADER_AUTHORITY_COUNT_OFFSET);
	break;
      }
    }
  }
  else {
    if (want_other(&control, dns_t_ns)) {
      cdb_findstart(&data_cdb);
      while ((r = find(&control, 0, &cur_find_type))) {
	if (r < 0) return 0;
	if (dns_type_equal(&cur_find_type, dns_t_ns)) {
	  if (!response_rr_start(&control, dns_t_ns, ttl)) return 0;
	  if (!do_name()) return 0;
	  response_rr_finish(DNS_HEADER_AUTHORITY_COUNT_OFFSET);
	}
      }
    }
  }
*/
/*
  if (flag_control_authoritative && (pos_authority == pos_answer)) {
    cdb_findstart(&data_cdb);
    while ((r = find(&control, 0, &cur_find_type))) {
      if (r < 0) return 0;
      if (dns_type_equal(&cur_find_type, dns_t_soa)) {
	if (!response_rr_start(&control, dns_t_soa, ttl)) return 0;
	if (!do_name()) return 0;
	if (!do_name()) return 0;
	if (!do_bytes(20)) return 0;
	response_rr_finish(DNS_HEADER_AUTHORITY_COUNT_OFFSET);
	break;
      }
    }
    if (want_other(&control, dns_t_ns)) {
      cdb_findstart(&data_cdb);
      while ((r = find(&control, 0, &cur_find_type))) {
	if (r < 0) return 0;
	if (dns_type_equal(&cur_find_type, dns_t_ns)) {
	  if (!response_rr_start(&control, dns_t_ns, ttl)) return 0;
	  if (!do_name()) return 0;
	  response_rr_finish(DNS_HEADER_AUTHORITY_COUNT_OFFSET);
	}
      }
    }
  }
*/
  pos_additional = response_len;

  bpos = pos_answer;
  while (bpos < pos_additional) {
    bpos = dns_packet_skipname(response, pos_additional, bpos);
    if (!bpos) return 0;
    bpos = dns_packet_copy(response, pos_additional, bpos, x, 10);
    if (!bpos) return 0;
    if (dns_type_equalb(dns_t_ns, x) || dns_type_equalb(dns_t_mx, x) || dns_type_equalb(dns_t_srv, x)) {
      if (dns_type_equalb(dns_t_mx, x)) {
        if (!safe_packet_getname(response, pos_additional, bpos + 2, &d1)) return 0;
      }
      else if (dns_type_equalb(dns_t_srv, x)) {
        if (!safe_packet_getname(response, pos_additional, bpos + 6, &d1)) return 0;
      }
      else {
        if (!safe_packet_getname(response, pos_additional, bpos, &d1)) return 0;
      }
      dns_domain_lower(&d1);

      if (want_other(&d1, dns_t_a)) {
        cdb_findstart(&data_cdb);
        while ((r = find(&d1, 0, &cur_find_type))) {
          if (r < 0) return 0;
          if (dns_type_equal(&cur_find_type, dns_t_a)) {
            if (!response_rr_start(&d1, dns_t_a, ttl)) return 0;
            if (!do_bytes(4)) return 0;
            response_rr_finish(DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
          }
        }
      }
      if (want_other(&d1, dns_t_aaaa)) {
        cdb_findstart(&data_cdb);
        while ((r = find(&d1, 0, &cur_find_type))) {
          if (r < 0) return 0;
          if (dns_type_equal(&cur_find_type, dns_t_aaaa)) {
            if (!response_rr_start(&d1, dns_t_aaaa, ttl)) return 0;
            if (!do_bytes(16)) return 0;
            response_rr_finish(DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
          }
        }
      }
    }
    uint16_unpack_big(&u16, x + 8);
    bpos += u16;
  }

  if (flag_edns0) {
    if (!response_opt_start(udp_size, DNS_RCODE_NOERROR)) return 0;
    response_opt_finish();
  }

  if (flag_control_authoritative && (response_len > udp_size)) {
    byte_zero(response + DNS_HEADER_ADDITIONAL_COUNT_OFFSET, 2);
    response_len = pos_additional;
    if (response_len > udp_size) {
      byte_zero(response + DNS_HEADER_AUTHORITY_COUNT_OFFSET, 2);
      response_len = pos_authority;
    }
  }

  return result;
}
