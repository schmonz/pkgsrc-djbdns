#include <nemo/stdint.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/fmt.h>
#include <nemo/ip4.h>
#include <nemo/char.h>

#include "dns.h"
#include "qlog.h"

void qlog_put(const void *buf, unsigned int len)
{
  djbio_put(djbiofd_err, buf, len);
}

static void qlog_puts(const char *s)
{
  djbio_puts(djbiofd_err, s);
}

static void qlog_putc(char c)
{
  djbio_put(djbiofd_err, &c, 1);
}
/*
static void qlog_hex(byte_t c)
{
  qlog_putc(char_hex_chars[(c >> 4) & 15]);
  qlog_putc(char_hex_chars[c & 15]);
}
*/
static void qlog_octal(byte_t c)
{
  qlog_putc('\\');
  qlog_putc(char_hex_chars[(c >> 6) & 7]);
  qlog_putc(char_hex_chars[(c >> 3) & 7]);
  qlog_putc(char_hex_chars[c & 7]);
}

static void qlog_number(unsigned int i)
{
  char misc[FMT_ULONG];
  qlog_put(misc, fmt_ulong(misc, i));
}

static void qlog_colon(void)
{
  djbio_put(djbiofd_err, ":", 1);
}

static void qlog_eol(void)
{
  djbio_put(djbiofd_err, "\n", 1);
  djbio_flush(djbiofd_err);
}

void qlog(uint16_t port, const dns_id *id, const dns_domain *qname, const dns_type *qtype, const char *result)
{
  const char *x;
  const byte_t *d;
  byte_t ch;
  byte_t ch2;
  unsigned int t;

  qlog_colon();
  qlog_number(port);
  qlog_colon();
  qlog_number(id->d);

  qlog_puts(result);

  t = dns_type_get(qtype);
  x = dns_type_str(t);
  if (x) {
    qlog_puts(x);
  }
  else {
    qlog_number(t);
  }
  qlog_putc(' ');

  d = qname->data;
  if (!*d) {
    qlog_putc('.');
  }
  else {
    for (;;) {
      ch = (byte_t)*d++;
      while (ch--) {
        ch2 = (byte_t)*d++;
        if ((ch2 >= 'A') && (ch2 <= 'Z')) {
          ch2 = (byte_t)(ch2 + 32);
        }
        if (((ch2 >= 'a') && (ch2 <= 'z')) || ((ch2 >= '0') && (ch2 <= '9')) || (ch2 == '-') || (ch2 == '_')) {
          qlog_putc((char)ch2);
        }
        else {
          qlog_octal(ch2);
        }
      }
      if (!*d) break;
      qlog_putc('.');
    }
  }

  qlog_eol();
}

void qlog_starting(const char *program)
{
  qlog_puts("starting ");
  qlog_puts(program);
  qlog_eol();
}

void qlog_putline(const char *s)
{
  qlog_puts(s);
  qlog_eol();
}
