/*
DNS should have used LZ77 instead of its own sophomoric compression algorithm.
*/

#include <nemo/error.h>

#include "dns.h"

static inline unsigned int proto_error(void)
{
  errno = error_proto;
  return 0;
}

unsigned int dns_packet_copy(const byte_t *buf, unsigned int len, unsigned int pos, byte_t *out, unsigned int out_len)
{
  while (out_len) {
    if (pos >= len) return proto_error();
    *out++ = buf[pos++];
    out_len--;
  }
  return pos;
}

unsigned int dns_packet_skipname(const byte_t *buf, unsigned int len, unsigned int pos)
{
  byte_t ch;
  for (;;) {
    if (pos >= len) break;
    ch = buf[pos++];
    if (ch >= 192) return pos + 1;
    if (ch >= 64) break;
    if (!ch) return pos;
    pos += ch;
  }
  return proto_error();
}

unsigned int dns_packet_getname(const byte_t *buf, unsigned int len, unsigned int pos, dns_domain *d)
{
  unsigned int loop;
  unsigned int state;
  unsigned int first_compress;
  unsigned int where;
  unsigned int name_len;
  byte_t name[255];
  byte_t ch;
  loop = state = first_compress = name_len = 0;
  if (!dns_domain_erase(d)) return 0;
  for (;;) {
    if (pos >= len) return proto_error();
    ch = buf[pos++];
    if (++loop >= 1000) return proto_error();
    if (state) {
      if (name_len + 1 > sizeof(name)) return proto_error();
      name[name_len++] = ch;
      state--;
    }
    else {
      while (ch >= 192) {
        where = ch;
        where -= 192;
        where <<= 8;
        if (pos >= len) return proto_error();
        ch = buf[pos++];
        if (!first_compress) {
          first_compress = pos;
        }
        pos = where + ch;
        if (pos >= len) return proto_error();
        ch = buf[pos++];
        if (++loop >= 1000) return proto_error();
      }
      if (ch >= 64) return proto_error();
      if (name_len + 1 > sizeof(name)) return proto_error();
      name[name_len++] = ch;
      if (!ch) break;
      state = ch;
    }
  }
  if (!dns_domain_copyb(d, name, name_len)) return 0;
  if (first_compress) return first_compress;
  return pos;
}
