#include <nemo/byte.h>
#include <nemo/error.h>
#include <nemo/stdint.h>
#include <nemo/uint16.h>

#include "dnscache.h"
#include "safe.h"

static inline unsigned int proto_error(void)
{
  errno = error_proto;
  return 0;
}

unsigned int packetquery(const byte_t *buf, unsigned int len, dns_domain *qname, dns_type *qtype, dns_class *qclass, dns_id *id, unsigned int *flag_edns0, unsigned int *udp_size)
{
  byte_t header[DNS_HEADER_SIZE];
  dns_type additional_section_type;
  unsigned int type;
  unsigned int i;
  unsigned int pos;
  unsigned int num_total;
  uint16_t num_answers;
  uint16_t num_authority;
  uint16_t num_additional;
  uint16_t rr_data_len;
  uint16_t udp_payload_size;

  udp_payload_size = 0;
  pos = dns_packet_copy(buf, len, 0, header, DNS_HEADER_SIZE);
  if (!pos) return proto_error();
  if (header[2] & 128) return proto_error();		/* must not respond to responses */
  if (!(header[2] & 1)) return proto_error();		/* ignore non-recursive queries */
  if (header[2] & 120) return proto_error();		/* ignore non-standard queries */
  if (header[2] & 2) return proto_error();		/* ignore truncation */
  if (header[4]) return proto_error();			/* ignore more than 1 question, part 1/2 */
  if (header[5] != '\001') return proto_error();	/* ignore more than 1 question, part 2/2 */

  dns_id_unpack(id, header);
  uint16_unpack_big(&num_answers, header + DNS_HEADER_ANSWER_COUNT_OFFSET);
  uint16_unpack_big(&num_authority, header + DNS_HEADER_AUTHORITY_COUNT_OFFSET);
  uint16_unpack_big(&num_additional, header + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
/*
  query section
*/
  pos = safe_packet_getname(buf, len, pos, qname);
  if (!pos) return proto_error();
  dns_domain_lower(qname);
  pos = dns_packet_copy(buf, len, pos, header, DNS_QUESTION_HEADER_SIZE);
  if (!pos) return proto_error();
  dns_type_unpack(qtype, header);
  type = dns_type_get(qtype);
  if (type == DNS_T_AXFR) return proto_error();			/* ignore AXFR */
  if (type == DNS_T_IXFR) return proto_error();			/* ignore IXFR */
  if (type == DNS_T_OPT) return proto_error();			/* ignore OPT in request, ok in additional section */
  if (type >= 65280 && type <= 65534) return proto_error();	/* ignore private use types */
  dns_class_unpack(qclass, header + 2);
  if (dns_class_diff(qclass, dns_c_in) && dns_class_diff(qclass, dns_c_any)) return proto_error();
/*
  answers + authority section
*/
  num_total = (unsigned int)num_answers + (unsigned int)num_authority;
  for (i = 0; i < num_total; i++) {
    pos = dns_packet_skipname(buf, len, pos);
    if (!pos) return proto_error();
    pos = dns_packet_copy(buf, len, pos, header, DNS_RR_HEADER_SIZE);  /* type, class, ttl, rr_data_len */
    if (!pos) return proto_error();
    uint16_unpack_big(&rr_data_len, header + DNS_RR_DATA_LENGTH_OFFSET);
    pos += rr_data_len;
    if (pos > len) return proto_error();  /* bad structure */
  }
/*
  additional section
*/
  *flag_edns0 = 0;
  for (i = 0; i < num_additional; i++) {
    pos = dns_packet_skipname(buf, len, pos);
    if (!pos) return proto_error();
    pos = dns_packet_copy(buf, len, pos, header, DNS_RR_HEADER_SIZE);  /* type, class, ttl, rr_data_len */
    if (!pos) return proto_error();
    dns_type_unpack(&additional_section_type, header);
    type = dns_type_get(&additional_section_type);
    if (type == DNS_T_OPT) {
      if (*flag_edns0) return proto_error();  /* multiple OPT RRs - bad structure*/
      uint16_unpack_big(&udp_payload_size, header + DNS_RR_CLASS_OFFSET);  /* class contains UDP payload size */
      *flag_edns0 = 1;
    }
    uint16_unpack_big(&rr_data_len, header + DNS_RR_DATA_LENGTH_OFFSET);
    pos += rr_data_len;
    if (pos > len) return proto_error();  /* bad structure */
  }
/*
  UPD size fixups
*/
  if (udp_payload_size < DNS_UDP_SIZE_DEFAULT) {  /* rfc6891 */
    udp_payload_size = DNS_UDP_SIZE_DEFAULT;
  }
  else if (udp_payload_size > DNS_UDP_SIZE_MAX) {
    udp_payload_size = DNS_UDP_SIZE_MAX;
  }
  *udp_size = udp_payload_size;

  return 1;
}
