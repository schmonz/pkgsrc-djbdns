#include <nemo/stdint.h>
#include <nemo/byte.h>
#include <nemo/uint16.h>
#include <nemo/uint32.h>

#include "response.h"
#include "die.h"

#define MAX_RESPONSE_LEN 65535

byte_t response[MAX_RESPONSE_LEN];
unsigned int response_len = 0;  /* <= 65535 */

static unsigned int tctarget;

static unsigned int dpos;

static unsigned int flag_hidettl = 0;

#define NAMES 100
static dns_domain name[NAMES];
static unsigned int name_ptr[NAMES];  /* each < 16384 */
static unsigned int name_num;

unsigned int response_addbytes(const void *buf, unsigned int len)
{
  if (len > MAX_RESPONSE_LEN - response_len) return 0;
  byte_copy(response + response_len, len, buf);
  response_len += len;
  return 1;
}

unsigned int response_adduint16(uint16_t u)
{
  byte_t data[2];

  uint16_pack_big(u, data);
  return response_addbytes(data, 2);
}

unsigned int response_addname(const dns_domain *dname)
{
/*
  return response_addbytes(dname->data, dns_domain_labellength(dname));
*/
  static dns_domain d = DNS_DOMAIN;
  unsigned int llen;
  unsigned int dlen;
  unsigned int i;
  byte_t buf[2];

  if (!dns_domain_copy(&d, dname)) die_nomem();

  while ((llen = dns_domain_labellength(&d))) {
    dlen = dns_domain_length(&d);
    for (i = 0; i < name_num; ++i) {
      if (dns_domain_equal(&d, &name[i])) {
        uint16_pack_big((uint16_t)(49152 + name_ptr[i]), buf);
        return response_addbytes(buf, 2);
      }
    }
    if ((dlen <= 128) && (response_len < 16384)) {
      if (name_num < NAMES) {
	if (!dns_domain_copy(&name[name_num], &d)) die_nomem();
	name_ptr[name_num] = response_len;
	++name_num;
      }
    }
    llen++;
    if (!response_addbytes(d.data, llen)) return 0;
    dns_domain_drop1label(&d);
  }
  return response_addbytes(d.data, 1);
}

unsigned int response_query(const dns_domain *qname, const dns_type *qtype, const dns_class *qclass)
{
  response_len = 0;
  name_num = 0;
  if (!response_addbytes("\000\000\201\200\000\001\000\000\000\000\000\000", 12)) return 0;
  if (!response_addname(qname)) return 0;
  if (!response_addtype(qtype)) return 0;
  if (!response_addclass(qclass)) return 0;
  tctarget = response_len;
  return 1;
}

void response_hidettl(void)
{
  flag_hidettl = 1;
}

unsigned int response_rr_start(const dns_domain *d, const dns_type *type, uint32_t ttl)
{
  byte_t ttl_data[4];

  if (!response_addname(d)) return 0;
  if (!response_addtype(type)) return 0;
  if (!response_addclass(dns_c_in)) return 0;
  if (flag_hidettl) {
    ttl = 0;
  }
  uint32_pack_big(ttl, ttl_data);
  if (!response_addbytes(ttl_data, 4)) return 0;
  if (!response_addbytes("\0\0", 2)) return 0;  /* RDLENGTH */
  dpos = response_len;
  return 1;
}

void response_rr_finish(unsigned int x)
{
  uint16_t u;

  uint16_pack_big((uint16_t)(response_len - dpos), response + dpos - 2);
/*
  if (!++response[x + 1]) {
    ++response[x];
  }
*/
  uint16_unpack_big(&u, response + x);
  u++;
  uint16_pack_big(u, response + x);
}

unsigned int response_opt_start(unsigned int udp_size, unsigned int rcode)
{
  byte_t extended_rcode;

  response[3] &= (byte_t)(~15);
  response[3] = (byte_t)(response[3] | (rcode & 15));

  if (!response_addname(dns_d_empty)) return 0;
  if (!response_addtype(dns_t_opt)) return 0;
  if (!response_adduint16((uint16_t)udp_size)) return 0;  /* in place of class - RFC6891 */
  extended_rcode = (byte_t)((rcode >> 4) & 0xff);
  if (!response_addbytes(&extended_rcode, 1)) return 0;
  if (!response_addbytes("\0\0\0\0\0", 5)) return 0;  /* VERSION + FLAGS + RDLENGTH */
  dpos = response_len;
  return 1;
}

void response_opt_finish(void)
{
  uint16_t u;

  uint16_pack_big((uint16_t)(response_len - dpos), response + dpos - 2);
  uint16_unpack_big(&u, response + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
  u++;
  uint16_pack_big(u, response + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
}

unsigned int response_opt_error(unsigned int rcode)
{
  byte_t extended_rcode;

  response[3] &= (byte_t)(~15);
  response[3] = (byte_t)(response[3] | (rcode & 15));
  response_len = tctarget;

  uint16_pack_big(0, response + DNS_HEADER_ANSWER_COUNT_OFFSET);
  uint16_pack_big(0, response + DNS_HEADER_AUTHORITY_COUNT_OFFSET);
  uint16_pack_big(1, response + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);

  if (!response_addname(dns_d_empty)) return 0;
  if (!response_addtype(dns_t_opt)) return 0;
  if (!response_addbytes("\0\0", 2)) return 0;  /* in place of class - RFC6891 */
  extended_rcode = (byte_t)((rcode >> 4) & 0xff);
  if (!response_addbytes(&extended_rcode, 1)) return 0;
  if (!response_addbytes("\0\0\0\0\0", 5)) return 0;  /* VERSION + FLAGS + RDLENGTH */
  return 1;
}

void response_nxdomain(void)
{
  response[3] &= (byte_t)(~15);
  response[3] |= DNS_RCODE_NXDOMAIN;
  response[2] |= 4;
}

void response_servfail(void)
{
  response[3] &= (byte_t)(~15);
  response[3] |= DNS_RCODE_SERVFAIL;
  response_len = tctarget;
  uint16_pack_big(0, response + DNS_HEADER_ANSWER_COUNT_OFFSET);
  uint16_pack_big(0, response + DNS_HEADER_AUTHORITY_COUNT_OFFSET);
  uint16_pack_big(0, response + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
}

void response_formerr(void)
{
  response[3] &= (byte_t)(~15);
  response[3] |= DNS_RCODE_FORMERR;
}

void response_notimp(void)
{
  response[3] &= (byte_t)(~15);
  response[3] |= DNS_RCODE_NOTIMP;
}

void response_refused(void)
{
  response[3] &= (byte_t)(~15);
  response[3] |= DNS_RCODE_REFUSED;
}

void response_id(const dns_id *id)
{
  dns_id_pack(id, response);
}

void response_tc(void)
{
  response[2] |= 2;
  response_len = tctarget;
  uint16_pack_big(0, response + DNS_HEADER_ANSWER_COUNT_OFFSET);
  uint16_pack_big(0, response + DNS_HEADER_AUTHORITY_COUNT_OFFSET);
  uint16_pack_big(0, response + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
}
