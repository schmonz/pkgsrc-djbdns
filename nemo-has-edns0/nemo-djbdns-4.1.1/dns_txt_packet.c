#include <nemo/stdint.h>
#include <nemo/uint16.h>

#include "dns.h"

int dns_txt_packet(sa_vector *out, const byte_t *buf, unsigned int len, const dns_type *type)
{
  static stralloc tmp = STRALLOC;

  byte_t header[12];
  unsigned int pos;
  unsigned int txt_len;
  unsigned int i;
  uint16_t num_answers;
  uint16_t rr_len;

  if (!sa_vector_erase(out)) return -1;

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
    if (dns_type_equalb(type, header)) {
      if (dns_class_equalb(dns_c_in, header + 2)) {
        if (pos + rr_len > len) return -1;
        if (!stralloc_erase(&tmp)) return -1;
        for (i = 0; i < rr_len; i += txt_len) {
          txt_len = buf[pos + i];
          i++;
          if (!stralloc_catb(&tmp, buf + pos + i, txt_len)) return -1;
        }
	stralloc_replace_non_printable(&tmp, '?');
	if (!sa_vector_append(out, &tmp)) return -1;
      }
    }
    pos += rr_len;
    num_answers--;
  }

  return 0;
}
