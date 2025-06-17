#include <nemo/error.h>
#include <nemo/byte.h>

#include "dns.h"
#include "printrecord.h"
#include "printpacket.h"
#include "safe.h"

#include <nemo/uint16.h>

static dns_domain d = DNS_DOMAIN;

#define X(s) if (!stralloc_cats(out, s)) return 0;
#define NUM(u) if (!stralloc_catulong0(out, u, 0)) return 0;

unsigned int printpacket_cat(const byte_t *buf, unsigned int len, stralloc *out)
{
  uint16_t num_queries;
  uint16_t num_answers;
  uint16_t num_authority;
  uint16_t num_additional;
  unsigned int pos;
  byte_t data[12];
  uint16_t type;

  pos = dns_packet_copy(buf, len, 0, data, 12);
  if (!pos) return 0;

  uint16_unpack_big(&num_queries, data + 4);
  uint16_unpack_big(&num_answers, data + 6);
  uint16_unpack_big(&num_authority, data + 8);
  uint16_unpack_big(&num_additional, data + 10);

  NUM(len)
  X(" bytes, ")
  NUM(num_queries)
  X("+")
  NUM(num_answers)
  X("+")
  NUM(num_authority)
  X("+")
  NUM(num_additional)
  X(" records")

  if (data[2] & 128) {
    X(", response")
  }
  if (data[2] & 120) {
    X(", weird op")
  }
  if (data[2] & 4) {
    X(", authoritative")
  }
  if (data[2] & 2) {
    X(", truncated")
  }
  if (data[2] & 1) {
    X(", weird rd")
  }
  if (data[3] & 128) {
    X(", weird ra")
  }
  switch (data[3] & 15) {
    case 0:
      X(", noerror")
      break;
    case 3:
      X(", nxdomain")
      break;
    case 4:
      X(", notimp")
      break;
    case 5:
      X(", refused")
      break;
    default:
      X(", weird rcode")
      break;
  }
  if (data[3] & 112) {
    X(", weird z")
  }

  X("\n")

  while (num_queries) {
    --num_queries;
    X("query: ")

    pos = safe_packet_getname(buf, len, pos, &d);
    if (!pos) return 0;
    pos = dns_packet_copy(buf, len, pos, data, 4);
    if (!pos) return 0;

    if (dns_class_diffb(dns_c_in, data + 2)) {
      X("weird class")
    }
    else {
      uint16_unpack_big(&type, data);
      NUM(type)
      X(" ")
      if (!dns_domain_todot_cat(&d, out)) return 0;
    }
    X("\n")
  }

  while (num_answers) {
    --num_answers;
    X("answer: ")
    pos = printrecord_cat(buf, len, pos, 0, 0, out);
    if (!pos) return 0;
  }

  while (num_authority) {
    --num_authority;
    X("authority: ")
    pos = printrecord_cat(buf, len, pos, 0, 0, out);
    if (!pos) return 0;
  }

  while (num_additional) {
    --num_additional;
    X("additional: ")
    pos = printrecord_cat(buf, len, pos, 0, 0, out);
    if (!pos) return 0;
  }

  if (pos != len) {
    errno = error_proto;
    return 0;
  }
  return 1;
}
