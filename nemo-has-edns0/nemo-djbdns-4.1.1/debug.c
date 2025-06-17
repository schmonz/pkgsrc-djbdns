#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/fmt.h>
#include <nemo/char.h>
#include <nemo/uint16.h>

#define DEBUG 1
#include "debug.h"

static inline void put_char(char ch)
{
  djbio_put(djbiofd_out, &ch, 1);
}
static inline void put_str(const char *s)
{
  djbio_puts(djbiofd_out, s);
}
static void put_ulong(unsigned long u)
{
  static char buffer[FMT_ULONG];
  djbio_put(djbiofd_out, buffer, fmt_ulong(buffer, u));
}
static void put_caption(const char *caption)
{
  put_char('#');
  put_str(caption);
  put_char(' ');
}
static inline void put_eol(void)
{
  put_char('\n');
  djbio_flush(djbiofd_out);
}
/*
static void debug_puts(const char *s)
{
  put_str(s);
}
*/
/*
static void put_octal_char(char c)
{
  char octal[4];
  octal[3] = char_hex_chars[c & '\007'];
  c >>= 3;
  octal[2] = char_hex_chars[c & '\007'];
  c >>= 3;
  octal[1] = char_hex_chars[c & '\007'];
  octal[0] = '\\';
  djbio_put(djbiofd_out, octal, sizeof(octal));
}
*/
/*
static void put_buffer(const char *s, unsigned int len)
{
  char x;
  while (len) {
    x = *s++;
    len--;
    if (!char_isprint(x)) {
      put_octal_char(x);
      continue;
    }
    put_char(x);
  }
}
*/
void debug_putsa(const char *caption, const stralloc *sa)
{
  put_caption(caption);
  djbio_putsa(djbiofd_out, sa);
  put_eol();
}
void debug_putint(const char *caption, int i)
{
  put_caption(caption);
  if (i < 0) {
    put_char('-');
    i = -i;
  }
  put_ulong((unsigned long)i);
  put_eol();
}
void debug_putuint(const char *caption, unsigned int u)
{
  put_caption(caption);
  put_ulong(u);
  put_eol();
}
void debug_putip4(const char *caption, const ip4_address *ip)
{
  char str[IP4_FMT];
  put_caption(caption);
  djbio_put(djbiofd_out, str, ip4_fmt(ip, str));
  put_eol();
}
void debug_putip6(const char *caption, const ip6_address *ip)
{
  char str[IP6_FMT];
  put_caption(caption);
  djbio_put(djbiofd_out, str, ip6_fmt(ip, str));
  put_eol();
}
static inline void put_domain(const dns_domain *dn)
{
  const byte_t *d;
  unsigned int plen;  /* prefix length */
  char ch;

  if (!dn->data || !dn->data[0]) {
    put_char('.');
    return;
  }
  d = dn->data;
  while ((plen = (unsigned int)*d++)) {
    while (plen) {
      ch = (char)*d++;
      plen--;
      if ((ch <= 32) || (ch > 126)) ch = '?';
      put_char(ch);
    }
    put_char('.');
  }
}
void debug_putdomain(const char *caption, const dns_domain *dn)
{
  put_caption(caption);
  put_domain(dn);
  put_eol();
}
static inline void put_type(const dns_type *type)
{
  const char *x;

  x = dns_type_str(type->d);
  if (x) {
    put_str(x);
  }
  else {
    put_ulong(type->d);
  }
}
void debug_puttype(const char *caption, const dns_type *type)
{
  put_caption(caption);
  put_type(type);
  put_eol();
}
void debug_putquery(const char *caption, const dns_domain *dn, const dns_type *t)
{
  put_caption(caption);
  put_type(t);
  put_char(' ');
  put_domain(dn);
  put_char(' ');
  put_eol();
}
void debug_putnumquery(const char *caption, uint64_t qn, const dns_domain *dn, const dns_type *t)
{
  put_caption(caption);
  put_ulong((unsigned long)qn);
  put_char(' ');
  put_type(t);
  put_char(' ');
  put_domain(dn);
  put_char(' ');
  put_eol();
}
