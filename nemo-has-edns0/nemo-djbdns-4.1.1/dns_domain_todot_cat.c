#include <nemo/stdint.h>
#include <nemo/char.h>

#include "dns.h"

unsigned int dns_domain_todot_cat(const dns_domain *dn, stralloc *out)
{
  const byte_t *d;
  byte_t buf[4];
  byte_t prefix_len;
  byte_t ch;
  byte_t octal;

  if (!dns_domain_active(dn) || !dns_domain_labellength(dn)) {
    return stralloc_append(out, ".");
  }

  d = dn->data;
  for (;;) {
    prefix_len = *d++;
    while (prefix_len--) {
      ch = *d++;
      if ((ch >= 'A') && (ch <= 'Z')) {
        ch = (byte_t)(ch + 32);
      }
      if (((ch >= 'a') && (ch <= 'z')) || ((ch >= '0') && (ch <= '9')) || (ch == '-') || (ch == '_')) {
        if (!stralloc_append(out, &ch)) return 0;
      }
      else {
        octal = ch;
        buf[3] = (byte_t)char_hex_chars[octal & '\007'];
        octal >>= 3;
        buf[2] = (byte_t)char_hex_chars[octal & '\007'];
        octal >>= 3;
        buf[1] = (byte_t)char_hex_chars[octal & '\007'];
        buf[0] = '\\';
        if (!stralloc_catb(out, buf, 4)) return 0;
      }
    }
    if (!*d) return 1;
    if (!stralloc_append(out, ".")) return 0;
  }
}
