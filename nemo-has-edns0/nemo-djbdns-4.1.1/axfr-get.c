#include <nemo/stdint.h>
#include <nemo/stralloc.h>
#include <nemo/error.h>
#include <nemo/djbio.h>
#include <nemo/getln.h>
#include <nemo/exit.h>
#include <nemo/open.h>
#include <nemo/scan.h>
#include <nemo/byte.h>
#include <nemo/str.h>
#include <nemo/timeoutio.h>
#include <nemo/unix.h>
#include <nemo/uint16.h>
#include <nemo/uint32.h>
#include <nemo/char.h>

#include "dns.h"
#include "die.h"
#include "safe.h"

const char USAGE[] = "zone fn fn.tmp";

static void die_generate(void)
{
  die_sys("unable to generate AXFR query");
}
static void die_axfr_parse(const char *errmsg)
{
  die_parse("AXFR results", errmsg);
}

static unsigned int x_copy(const void *buf, unsigned int len, unsigned int pos, void *out, unsigned int outlen)
{
  pos = dns_packet_copy(buf, len, pos, out, outlen);
  if (!pos) die_axfr_parse("empty packet");
  return pos;
}
static unsigned int x_getname(const void *buf, unsigned int len, unsigned int pos, dns_domain *out)
{
  pos = safe_packet_getname(buf, len, pos, out);
  if (!pos) die_axfr_parse("empty name");
  return pos;
}
static unsigned int x_skipname(const void *buf, unsigned int len, unsigned int pos)
{
  pos = dns_packet_skipname(buf, len, pos);
  if (!pos) die_axfr_parse("empty skip name");
  return pos;
}

static dns_domain zone = DNS_DOMAIN;

static char *fn;
static char *fntmp;

static ssize_t saferead(int fd, void *buf, size_t len)
{
  ssize_t r;
  r = timeoutio_read(60, fd, buf, len);
  if (r == 0) die_axfr_parse("empty packet");
  if (r < 0) die_read("network");
  return r;
}
static ssize_t safewrite(int fd, const void *buf, size_t len)
{
  ssize_t r;
  r = timeoutio_write(60, fd, buf, len);
  if (r <= 0) die_write("network");
  return r;
}

static byte_t netreadspace[1024];
static djbio netread = DJBIO_INITREAD(saferead, 6, netreadspace, sizeof netreadspace);
static byte_t netwritespace[1024];
static djbio netwrite = DJBIO_INITWRITE(safewrite, 7, netwritespace, sizeof netwritespace);

static void netget(void *out, unsigned int len)
{
  byte_t *buf;
  int r;
  buf = out;
  while (len > 0) {
    r = djbio_get(&netread, buf, len);
    buf += r;
    len -= (unsigned int)r;
  }
}

static int fd;
static djbio ssio;
static byte_t bspace[1024];

static void putsa(const stralloc *sa)
{
  if (djbio_putsa(&ssio, sa) < 0) die_write(fntmp);
}

static unsigned int printable(byte_t ch)
{
  if (ch == '.') return 1;
  if ((ch >= 'a') && (ch <= 'z')) return 1;
  if ((ch >= '0') && (ch <= '9')) return 1;
  if ((ch >= 'A') && (ch <= 'Z')) return 1;
  if (ch == '-') return 1;
  if (ch == '_') return 1;
  if (ch == ' ') return 1;
  if (ch == '=') return 1;
  return 0;
}

static dns_domain d1 = DNS_DOMAIN;
static dns_domain d2 = DNS_DOMAIN;
static dns_domain d3 = DNS_DOMAIN;

static stralloc line;
static unsigned int match;

static int num_soa;

static void line_append_colon(void)
{
  if (!stralloc_append(&line, ":")) die_nomem();
}
static void line_append_dot(void)
{
  if (!stralloc_append(&line, ".")) die_nomem();
}
static void line_append_byte(byte_t c)
{
  if (!stralloc_append(&line, &c)) die_nomem();
}
static void line_append_safechar(byte_t ch)
{
  byte_t data[4];

  if (printable(ch)) {
    if (!stralloc_catb(&line, &ch, 1)) die_nomem();
    return;
  }
  data[3] = (byte_t)char_hex_chars[7 & ch];
  ch >>= 3;
  data[2] = (byte_t)char_hex_chars[7 & ch];
  ch >>= 3;
  data[1] = (byte_t)char_hex_chars[7 & ch];
  data[0] = '\\';
  if (!stralloc_catb(&line, data, 4)) die_nomem();
}

static void line_copy_byte(byte_t c)
{
  if (!stralloc_copyb(&line, &c, 1)) die_nomem();
}
static void line_copy_string(const char *s)
{
  if (!stralloc_copys(&line, s)) die_nomem();
}

static unsigned int doit(char *buf, unsigned int len, unsigned int pos)
{
  byte_t flags[255];
  byte_t service[255];
  byte_t regexp[255];
  char ipstr[IP6_FMT];
  byte_t data[20];
  dns_type type;
  dns_class class;
  ip4_address ip4;
  ip6_address ip6;
  uint32_t ttl;
  uint32_t u32;
  uint16_t dlen;
  uint16_t dist;
  uint16_t weight;
  uint16_t port;
  uint16_t order;
  uint16_t preference;
  unsigned int i;
  unsigned int k;
  byte_t ch;
  byte_t fs;
  byte_t ss;
  byte_t rs;

  pos = x_getname(buf, len, pos, &d1);
  pos = x_copy(buf, len, pos, data, 10);
  dns_type_unpack(&type, data);
  dns_class_unpack(&class, data + 2);
  uint32_unpack_big(&ttl, data + 4);
  uint16_unpack_big(&dlen, data + 8);
  if (len - pos < dlen) die_axfr_parse("invalid data length");
  len = pos + dlen;

  if (!dns_domain_suffix(&d1, &zone)) return len;
  if (dns_class_diff(&class, dns_c_in)) return len;

  switch (dns_type_get(&type)) {
    case DNS_T_SOA:
      if (++num_soa >= 2) return len;
      pos = x_getname(buf, len, pos, &d2);
      pos = x_getname(buf, len, pos, &d3);
      x_copy(buf, len, pos, data, 20);
      uint32_unpack_big(&u32, data);
      line_copy_byte('#');
      if (!stralloc_catulong0(&line, u32, 0)) die_nomem();
      if (!stralloc_cats(&line, " auto axfr-get\n")) die_nomem();
      line_copy_byte('Z');
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      if (!dns_domain_todot_cat(&d2, &line)) die_nomem();
      line_append_dot();
      line_append_colon();
      if (!dns_domain_todot_cat(&d3, &line)) die_nomem();
      line_append_dot();
      for (i = 0; i < 5; ++i) {
        uint32_unpack_big(&u32, data + 4 * i);
        line_append_colon();
        if (!stralloc_catulong0(&line, u32, 0)) die_nomem();
      }
      break;

    case DNS_T_NS:
      line_copy_byte('&');
      line_append_colon();
      if (byte_equal(d1.data, 2, "\1*")) die_axfr_parse("wild card NS");
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      line_append_colon();
      x_getname(buf, len, pos, &d1);
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_dot();
      break;

    case DNS_T_CNAME:
      line_copy_byte('C');
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      x_getname(buf, len, pos, &d1);
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_dot();
      break;

    case DNS_T_PTR:
      line_copy_byte('^');
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      x_getname(buf, len, pos, &d1);
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_dot();
      break;

    case DNS_T_MX:
      line_copy_byte('@');
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      line_append_colon();
      pos = x_copy(buf, len, pos, data, 2);
      uint16_unpack_big(&dist, data);
      x_getname(buf, len, pos, &d1);
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_dot();
      line_append_colon();
      if (!stralloc_catulong0(&line, dist, 0)) die_nomem();
      break;

    case DNS_T_A:
      if (dlen == 4) {
        line_copy_byte('+');
        line_append_colon();
        if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
        line_append_colon();
        x_copy(buf, len, pos, data, 4);
        ip4_unpack(&ip4, data);
        if (!stralloc_catb(&line, ipstr, ip4_fmt(&ip4, ipstr))) die_nomem();
      }
      break;

    case DNS_T_AAAA:
      if (dlen == 16) {
	line_copy_byte('3');
        line_append_colon();
	if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
	line_append_colon();
	x_copy(buf, len, pos, data, 16);
	ip6_unpack(&ip6, data);
	line_append_byte('[');
	if (!stralloc_catb(&line, ipstr, ip6_fmt(&ip6, ipstr))) die_nomem();
	line_append_byte(']');
      }
      break;

    case DNS_T_TXT:
      line_copy_byte('\'');
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      k = 0;
      for (i = 0; i < dlen; ++i) {
        pos = x_copy(buf, len, pos, &ch, 1);
        if (!k) {
          k = (byte_t)ch;  /* char str len */
          continue;
        }
        k--;
        line_append_safechar(ch);
      }
      break;

    case DNS_T_CAA:
      line_copy_string("CAA");
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      pos = x_copy(buf, len, pos, &ch, 1);
      if (!stralloc_catulong0(&line, ch, 0)) die_nomem();
      line_append_colon();
      pos = x_copy(buf, len, pos, &ch, 1);
      k = ch;
      for (i = 0; i < k; ++i) {
        pos = x_copy(buf, len, pos, &ch, 1);
        line_append_safechar(ch);
      }
      line_append_colon();
      for (i = 2 + k; i < dlen; ++i) {
        pos = x_copy(buf, len, pos, &ch, 1);
        line_append_safechar(ch);
      }
      break;

    case DNS_T_SRV:
      line_copy_string("SRV");
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      line_append_colon();
      pos = x_copy(buf, len, pos, data, 2);
      uint16_unpack_big(&dist, data);
      pos = x_copy(buf, len, pos, data, 2);
      uint16_unpack_big(&weight, data);
      pos = x_copy(buf, len, pos, data, 2);
      uint16_unpack_big(&port, data);
      x_getname(buf, len, pos, &d1);
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_dot();
      line_append_colon();
      if (!stralloc_catulong0(&line, dist,0)) die_nomem();
      line_append_colon();
      if (!stralloc_catulong0(&line, weight, 0)) die_nomem();
      line_append_colon();
      if (!stralloc_catulong0(&line, port, 0)) die_nomem();
      break;

    case DNS_T_NAPTR:
      line_copy_string("NAPTR");
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      pos = x_copy(buf, len, pos, data, 2);
      uint16_unpack_big(&order, data);
      pos = x_copy(buf, len, pos, data, 2);
      uint16_unpack_big(&preference, data);
      pos = x_copy(buf, len, pos, &fs, 1);
      pos = x_copy(buf, len, pos, flags, (unsigned int)fs);
      pos = x_copy(buf, len, pos, &ss, 1);
      pos = x_copy(buf, len, pos, service, (unsigned int)ss);
      pos = x_copy(buf, len, pos, &rs, 1);
      pos = x_copy(buf, len, pos, regexp, (unsigned int)rs);
      x_getname(buf, len, pos, &d1);
      if (!stralloc_catulong0(&line, order, 0)) die_nomem();
      line_append_colon();
      if (!stralloc_catulong0(&line, preference, 0)) die_nomem();
      line_append_colon();
      if (!stralloc_catb(&line, flags, (unsigned int)fs)) die_nomem();
      line_append_colon();
      if (!stralloc_catb(&line, service, (unsigned int)ss)) die_nomem();
      line_append_colon();
      if (!stralloc_catb(&line, regexp, (unsigned int)rs)) die_nomem();
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_dot();
      break;
/*
    case DNS_T_SPF:
      line_copy_string("SPF");
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      k = 0;
      for (i = 0; i < dlen; ++i) {
        pos = x_copy(buf, len, pos, &ch, 1);
        if (!k) {
          k = (byte_t)ch;
          continue;
        }
        k--;
        line_append_safechar(ch);
      }
      break;
*/
    default:
      line_copy_byte('?');
      line_append_colon();
      if (!dns_domain_todot_cat(&d1, &line)) die_nomem();
      line_append_colon();
      if (!stralloc_catulong0(&line, dns_type_get(&type), 0)) die_nomem();
      line_append_colon();
      for (i = 0; i < dlen; ++i) {
        pos = x_copy(buf, len, pos, &ch, 1);
        line_append_safechar(ch);
      }
      break;
  }
  line_append_colon();
  if (!stralloc_catulong0(&line, ttl, 0)) die_nomem();
  line_append_byte('\n');
  putsa(&line);

  return len;
}

static stralloc packet;

int main(int argc, char **argv)
{
  byte_t out[20];
  unsigned long u;
  uint16_t dlen;
  unsigned int pos;
  uint32_t old_serial;
  uint32_t new_serial;
  uint16_t num_queries;
  uint16_t num_answers;

  PROGRAM = *argv;
  old_serial = new_serial = 0;

  if (!argc) die_usage();

  if (!*++argv) die_usage1("missing zone parameter");
  if (!dns_domain_fromdot(&zone, *argv, str_len(*argv))) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_parse("bad zone name", *argv);
    die_usage1("malformed zone name");
  }

  if (!*++argv) die_usage1("missing file parameter");
  fn = *argv;
  if (!*++argv) die_usage1("missing temporary file parameter");
  fntmp = *argv;

  fd = open_read(fn);
  if (fd < 0) {
    if (errno != error_noent) die_read(fn);
  }
  else {
    djbio_initread(&ssio, read, fd, bspace, sizeof bspace);
    if (getln(&ssio, &line, &match, '\n') < 0) die_read(fn);
    if (!stralloc_0(&line)) die_read(fn);
    if (line.s[0] == '#') {
      scan_ulong(line.s + 1, &u);
      old_serial = (uint32_t)u;
    }
    close(fd);
  }

  if (!stralloc_copyb(&packet, "\0\0\0\0\0\1\0\0\0\0\0\0", 12)) die_generate();
  if (!stralloc_catb(&packet, zone.data, zone.len)) die_generate();
  dns_type_pack(dns_t_soa, out);
  if (!stralloc_catb(&packet, out, 2)) die_generate();
  dns_class_pack(dns_c_in, out);
  if (!stralloc_catb(&packet, out, 2)) die_generate();
  uint16_pack_big((uint16_t)packet.len, out);
  djbio_put(&netwrite, out, 2);
  djbio_putsa(&netwrite, &packet);
  djbio_flush(&netwrite);

  netget(out, 2);
  uint16_unpack_big(&dlen, out);
  if (!stralloc_ready(&packet, dlen)) die_nomem();
  netget(packet.s, dlen);
  packet.len = dlen;

  pos = x_copy(packet.s, packet.len, 0, out, 12);
  uint16_unpack_big(&num_queries, out + 4);
  uint16_unpack_big(&num_answers, out + 6);

  while (num_queries) {
    --num_queries;
    pos = x_skipname(packet.s, packet.len, pos);
    pos += 4;
  }

  if (!num_answers) die_axfr_parse("zero answers");
  pos = x_getname(packet.s, packet.len, pos, &d1);
  if (!dns_domain_equal(&zone, &d1)) die_axfr_parse("response not matching query zone");
  pos = x_copy(packet.s, packet.len, pos, out, 10);
  if (dns_type_diffb(dns_t_soa, out)) die_axfr_parse("response type not SOA");
  if (dns_class_diffb(dns_c_in, out + 2)) die_axfr_parse("response class not IN");
  pos = x_skipname(packet.s, packet.len, pos);
  pos = x_skipname(packet.s, packet.len, pos);
  pos = x_copy(packet.s, packet.len, pos, out, 4);

  uint32_unpack_big(&new_serial, out);

  if (old_serial && new_serial) {  /* allow 0 for very recently modified zones */
    if (old_serial == new_serial) {  /* allow serial numbers to move backwards */
      _exit(0);
    }
  }

  fd = open_trunc(fntmp);
  if (fd < 0) die_write(fntmp);
  djbio_initwrite(&ssio, write, fd, bspace, sizeof bspace);

  if (!stralloc_copyb(&packet, "\0\0\0\0\0\1\0\0\0\0\0\0", 12)) die_generate();
  if (!stralloc_catb(&packet, zone.data, zone.len)) die_generate();
  dns_type_pack(dns_t_axfr, out);
  if (!stralloc_catb(&packet, out, 2)) die_generate();
  dns_class_pack(dns_c_in, out);
  if (!stralloc_catb(&packet, out, 2)) die_generate();
  uint16_pack_big((uint16_t)packet.len, out);
  djbio_put(&netwrite, out, 2);
  djbio_putsa(&netwrite, &packet);
  djbio_flush(&netwrite);

  num_soa = 0;
  while (num_soa < 2) {
    netget(out, 2);
    uint16_unpack_big(&dlen, out);
    if (!stralloc_ready(&packet, dlen)) die_nomem();
    netget(packet.s, dlen);
    packet.len = dlen;

    pos = x_copy(packet.s, packet.len, 0, out, 12);
    uint16_unpack_big(&num_queries, out + 4);

    while (num_queries) {
      --num_queries;
      pos = x_skipname(packet.s, packet.len, pos);
      pos += 4;
    }
    while (pos < packet.len) {
      pos = doit(packet.s, packet.len, pos);
    }
  }

  if (djbio_flush(&ssio) < 0) die_write(fntmp);
  if (fsync(fd) < 0) die_write(fntmp);
  if (close(fd) < 0) die_write(fntmp);  /* NFS dorks */
  if (rename(fntmp, fn) < 0) die_move(fntmp, fn);
  _exit(0);
}
