#include <nemo/stdint.h>
#include <nemo/error.h>
#include <nemo/byte.h>
#include <nemo/char.h>

#include "dns.h"

static unsigned int bad_proto(void)
{
  errno = error_proto;
  return 0;
}

unsigned int dns_domain_fromdot(dns_domain *out, const void *d, unsigned int buf_len)
{
  const byte_t *buf;
  byte_t label[63];
  unsigned int label_len;  /* <= sizeof label */
  byte_t name[255];
  unsigned int name_len;  /* <= sizeof name */
  unsigned int is_octal;
  byte_t ch;
  byte_t octal;
  byte_t nibble;

  buf = d;
  label_len = name_len = 0;
  is_octal = 0;
  while (buf_len) {
    ch = *buf++;
    buf_len--;
    if (is_octal) {
      nibble = char_hex_table[ch];
      if (nibble > 7) return bad_proto();
      octal = (byte_t)(octal << 3) | nibble;
      if (is_octal++ < 3) continue;
      ch = octal;
      is_octal = 0;
    }
    else if (ch == '\\') {  /* octal decode */
      octal = 0;
      is_octal = 1;
      continue;
    }
    if (ch == '.') {
      if (!label_len) {
        if (name_len || buf_len) return bad_proto();  /* empty labels forbidden, except for root aka '.' */
        continue;
      }
      if ((name_len + label_len + 1) > sizeof(name)) return bad_proto();
      name[name_len++] = (byte_t)label_len;
      byte_copy(name + name_len, label_len, label);
      name_len += label_len;
      label_len = 0;
      continue;
    }
    if (label_len > sizeof(label)) return bad_proto();
    label[label_len++] = ch;
  }

  if (is_octal) return bad_proto();

  if (label_len) {
    if ((name_len + label_len + 1) > sizeof(name)) return bad_proto();
    name[name_len++] = (byte_t)label_len;
    byte_copy(name + name_len, label_len, label);
    name_len += label_len;
  }

  if ((name_len + 1) > sizeof(name)) return bad_proto();
  name[name_len++] = '\0';

  return dns_domain_copyb(out, name, name_len);
}
