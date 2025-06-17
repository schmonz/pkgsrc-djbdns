#include <nemo/stdint.h>
#include <nemo/uint16.h>

#include "dns.h"

int dns_mx_packet(mxname_vector *out, const byte_t *buf, unsigned int len)
{
  static stralloc tmp = STRALLOC;
  static dns_domain q = DNS_DOMAIN;

  unsigned int pos;
  unsigned int pref;
  byte_t header[12];
  byte_t pref_data[2];
  uint16_t num_answers;
  uint16_t rr_len;

  if (!mxname_vector_erase(out)) return -1;

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
    uint16_unpack_big(&rr_len, header + 8);
    if (dns_type_equalb(dns_t_mx, header)) {
      if (dns_class_equalb(dns_c_in, header + 2)) {
	if (!dns_packet_copy(buf, len, pos, pref_data, 2)) return -1;
	if (!dns_packet_getname(buf, len, pos + 2, &q)) return -1;
	if (!stralloc_erase(&tmp)) return -1;
	if (!dns_domain_todot_cat(&q, &tmp)) return -1;
        pref = pref_data[0];
        pref <<= 8;
        pref += pref_data[1];
	if (!mxname_vector_append(out, &tmp, pref)) return -1;
      }
    }
    pos += rr_len;
    num_answers--;
  }

  return 0;
}
