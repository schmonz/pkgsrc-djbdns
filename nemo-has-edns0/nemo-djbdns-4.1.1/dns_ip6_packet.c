#include <nemo/stdint.h>
#include <nemo/uint16.h>

#include "dns.h"

int dns_ip6_packet(ip6_vector *out, const byte_t *buf, unsigned int len)
{
  byte_t header[16];
  ip6_address ip;
  unsigned int pos;
  uint16_t num_answers;
  uint16_t rr_len;

  if (!ip6_vector_erase(out)) return -1;

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
    if (dns_type_equalb(dns_t_aaaa, header)) {
      if (dns_class_equalb(dns_c_in, header + 2)) {
        if (rr_len == 16) {
          if (!dns_packet_copy(buf, len, pos, header, 16)) return -1;
          ip6_unpack(&ip, header);
	  if (!ip6_vector_append(out, &ip)) return -1;
        }
      }
    }
    pos += rr_len;
    num_answers--;
  }

  dns_sortip6(out);
  return 0;
}
