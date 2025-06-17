#include <nemo/stdint.h>
#include <nemo/uint16.h>
#include <nemo/uint32.h>
#include <nemo/uint_vector.h>
#include <nemo/byte.h>

#include "dns.h"
#include "cache.h"
#include "safe.h"
#include "die.h"

#include "ioquery_havepacket.h"

unsigned int *records = 0;
unsigned int rr_count = 0;

static uint_vector rr_list = UINT_VECTOR;

static dns_domain tname1 = DNS_DOMAIN;
static dns_domain tname2 = DNS_DOMAIN;

static byte_t save_buf[8192];
static unsigned int save_len;
static unsigned int save_ok;

static unsigned int opt_count;

unsigned int ioquery_opt_count(void)
{
  return opt_count;
}

void ioquery_save_start(void)
{
  save_len = 0;
  save_ok = 1;
}

void ioquery_save_data(const byte_t *buf, unsigned int len)
{
  if (!save_ok) return;
  if (len > (sizeof save_buf) - save_len) {
    save_ok = 0;
    return;
  }
  byte_copy(save_buf + save_len, len, buf);
  save_len += len;
}

void ioquery_save_finish(const dns_type *type, const dns_domain *d, uint32_t ttl)
{
  if (!save_ok) return;
  cache_generic(type, d, save_buf, save_len, ttl);
}

uint32_t ioquery_ttl_get(byte_t *buf)
{
  uint32_t ttl;

  uint32_unpack_big(&ttl, buf);
  if (ttl > 1000000000) return 0;
  if (ttl > 604800) return 604800;
  return ttl;
}

static void process_opt_record(void)
{
  /* ignore size returned */
  opt_count++;
}

static unsigned int rr_ok(unsigned int type)
{
  if (type == DNS_T_ANY) return 0;
  if (type == DNS_T_AXFR) return 0;
  if (type == DNS_T_IXFR) return 0;
  if (type == DNS_T_OPT) return 0;
  return 1;
}

unsigned int ioquery_scan_records(const byte_t *buf, unsigned int len, unsigned int start, unsigned int query_type,
					unsigned int num_answers, unsigned int num_authority, unsigned int num_additional,
					unsigned int *flag_found, unsigned int *flag_soa, unsigned int *flag_referral,
					uint32_t *soa_ttl, unsigned int *pos_authority)
{
  byte_t header[DNS_RR_HEADER_SIZE];
  dns_type rr_type;
  unsigned int ttype;
  unsigned int j;
  unsigned int pos;
  unsigned int rr_pos;
  unsigned int flag_any;
  uint16_t data_len;

  opt_count = 0;
  if (!uint_vector_erase(&rr_list)) die_nomem();
  if (!dns_domain_erase(&referral)) die_nomem();
  pos = start;

  flag_any = (query_type == DNS_T_ANY);
  *flag_found = *flag_referral = *flag_soa = 0;
  *soa_ttl = 0;
/*
  This code assumes that the CNAME chain is presented in the correct
  order.  The example algorithm in RFC 1034 will actually result in this
  being the case, but the words do not require it to be so.
*/
  for (j = 0; j < num_answers; ++j) {
    rr_pos = pos;
    pos = safe_packet_getname(buf, len, pos, &tname1);
    if (!pos) return 0;
    pos = dns_packet_copy(buf, len, pos, header, DNS_RR_HEADER_SIZE);
    if (!pos) return 0;
    dns_type_unpack(&rr_type, header);
    ttype = dns_type_get(&rr_type);
    if (rr_ok(ttype)) {
      if (dns_domain_equal(&tname1, &owner_name)) {
	if (dns_class_equalb(dns_c_in, header + 2)) {  /* should always be true */
	  if (flag_any || ttype == query_type) {
	    *flag_found = 1;
	  }
	  else if (ttype == DNS_T_CNAME) {
	    if (!safe_packet_getname(buf, len, pos, &owner_name)) return 0;
	    /* don't update pos here; see below */
	    *flag_found = 1;
	  }
	}
      }
      if (!uint_vector_append(&rr_list, rr_pos)) die_nomem();
    }
    uint16_unpack_big(&data_len, header + 8);
    pos += data_len;
  }
/*
  authority section
*/
  *pos_authority = pos;
  for (j = 0; j < num_authority; ++j) {
    rr_pos = pos;
    pos = safe_packet_getname(buf, len, pos, &tname1);
    if (!pos) return 0;
    pos = dns_packet_copy(buf, len, pos, header, DNS_RR_HEADER_SIZE);
    if (!pos) return 0;
    dns_type_unpack(&rr_type, header);
    ttype = dns_type_get(&rr_type);
    if (rr_ok(ttype)) {
      if (ttype == DNS_T_SOA) {
	*flag_soa = 1;
	*soa_ttl = ioquery_ttl_get(header + 4);
	if (*soa_ttl > 3600) {
	  *soa_ttl = 3600;
	}
      }
      else if (ttype == DNS_T_NS) {
	*flag_referral = 1;
	if (!dns_domain_copy(&referral, &tname1)) die_nomem();
      }
      if (!uint_vector_append(&rr_list, rr_pos)) die_nomem();
    }
    uint16_unpack_big(&data_len, header + 8);
    pos += data_len;
  }
/*
  additional section
*/
  for (j = 0; j < num_additional; ++j) {
    rr_pos = pos;
    pos = safe_packet_getname(buf, len, pos, &tname1);
    if (!pos) return 0;
    pos = dns_packet_copy(buf, len, pos, header, DNS_RR_HEADER_SIZE);
    if (!pos) return 0;
    dns_type_unpack(&rr_type, header);
    ttype = dns_type_get(&rr_type);
    if (ttype == DNS_T_OPT) {
      process_opt_record();
    }
    else if (rr_ok(ttype)) {
      if (!uint_vector_append(&rr_list, rr_pos)) die_nomem();
    }
    uint16_unpack_big(&data_len, header + 8);
    pos += data_len;
  }
/*
  finish
*/
  records = rr_list.va;
  rr_count = rr_list.len;

  return 1;
}

static unsigned int smaller(const byte_t *buf, unsigned int len, unsigned int pos1, unsigned int pos2)
{
  byte_t header1[DNS_RR_HEADER_SIZE];
  byte_t header2[DNS_RR_HEADER_SIZE];
  int r;
  unsigned int len1;
  unsigned int len2;

  pos1 = safe_packet_getname(buf, len, pos1, &tname1);
  dns_packet_copy(buf, len, pos1, header1, DNS_RR_HEADER_SIZE);
  pos2 = safe_packet_getname(buf, len, pos2, &tname2);
  dns_packet_copy(buf, len, pos2, header2, DNS_RR_HEADER_SIZE);

  r = byte_diff(header1, 4, header2);
  if (r < 0) return 1;
  if (r > 0) return 0;

  len1 = tname1.len;
  len2 = tname2.len;
  if (len1 < len2) return 1;
  if (len1 > len2) return 0;

  r = byte_case_diff(tname1.data, len1, tname2.data);
  if (r < 0) return 1;
  if (r > 0) return 0;

  if (pos1 < pos2) return 1;
  return 0;
}

void ioquery_sort_records(const byte_t *buf, unsigned int len, unsigned int num_total)
{
  unsigned int i;
  unsigned int j;
  unsigned int p;
  unsigned int q;
  unsigned int pos;

  i = j = num_total;
  while (j > 1) {
    if (i > 1) {
      --i;
      pos = records[i - 1];
    }
    else {
      pos = records[j - 1];
      records[j - 1] = records[i - 1];
      --j;
    }

    q = i;
    while ((p = q * 2) < j) {
      if (!smaller(buf, len, records[p], records[p - 1])) {
        ++p;
      }
      records[q - 1] = records[p - 1];
      q = p;
    }
    if (p == j) {
      records[q - 1] = records[p - 1];
      q = p;
    }
    while ((q > i) && smaller(buf, len, records[(p = q/2) - 1], pos)) {
      records[q - 1] = records[p - 1];
      q = p;
    }
    records[q - 1] = pos;
  }
}

unsigned int ignore_ip4(const ip4_address *ip)
{
  return (ip4_vector_find(&ignore_ip4_list, ip) != ignore_ip4_list.len);
}

unsigned int ignore_ip6(const ip6_address *ip)
{
  return (ip6_vector_find(&ignore_ip6_list, ip) != ignore_ip6_list.len);
}
