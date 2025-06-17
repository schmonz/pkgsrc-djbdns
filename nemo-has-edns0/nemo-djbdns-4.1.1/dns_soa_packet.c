#include <nemo/stdint.h>
#include <nemo/uint16.h>
#include <nemo/uint32.h>

#include "dns.h"

int dns_soa_packet(soa_vector *out, const byte_t *buf, unsigned int len)
{
  static stralloc tmp = STRALLOC;
  static dns_domain q = DNS_DOMAIN;
  static soa_data soa = SOA_DATA;

  unsigned int pos;
  unsigned int old_pos;
  byte_t header[12];
  byte_t misc[4];
  uint16_t num_answers;
  uint16_t rr_len;

  if (!soa_vector_erase(out)) return -1;

  pos = dns_packet_copy(buf, len, 0, header, 12);
  if (!pos) return -1;
  uint16_unpack_big(&num_answers, header + 6);
  pos = dns_packet_skipname(buf, len, pos);
  if (!pos) return -1;
  pos += 4;

  while (num_answers) {
    pos = dns_packet_skipname(buf, len, pos);
    if (!pos) return -1;
    pos = dns_packet_copy(buf, len, pos, header, 10);
    if (!pos) return -1;
    old_pos = pos;
    uint16_unpack_big(&rr_len, header + 8);
    if (dns_type_equalb(dns_t_soa, header)) {
      if (dns_class_equalb(dns_c_in, header + 2)) {
	pos = dns_packet_getname(buf, len, pos, &q);
	if (!pos) return -1;
        if (!stralloc_erase(&tmp)) return -1;
	if (!dns_domain_todot_cat(&q, &tmp)) return -1;
	if (!stralloc_copy(&soa.mname, &tmp)) return -1;
	pos = dns_packet_getname(buf, len, pos, &q);
	if (!pos) return -1;
        if (!stralloc_erase(&tmp)) return -1;
	if (!dns_domain_todot_cat(&q, &tmp)) return -1;
	if (!stralloc_copy(&soa.rname, &tmp)) return -1;
	pos = dns_packet_copy(buf, len, pos, misc, 4);
	if (!pos) return -1;
	uint32_unpack_big(&soa.serial, misc);
	pos = dns_packet_copy(buf, len, pos, misc, 4);
	if (!pos) return -1;
	uint32_unpack_big(&soa.refresh, misc);
	pos = dns_packet_copy(buf, len, pos, misc, 4);
	if (!pos) return -1;
	uint32_unpack_big(&soa.retry, misc);
	pos = dns_packet_copy(buf, len, pos, misc, 4);
	if (!pos) return -1;
	uint32_unpack_big(&soa.expire, misc);
	pos = dns_packet_copy(buf, len, pos, misc, 4);
	if (!pos) return -1;
	uint32_unpack_big(&soa.minimum, misc);
	if (!soa_vector_append(out, &soa)) return -1;
      }
    }
    pos = old_pos + rr_len;
    num_answers--;
  }

  return 0;
}
