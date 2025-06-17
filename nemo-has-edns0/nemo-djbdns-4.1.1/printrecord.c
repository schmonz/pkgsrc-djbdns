#include <nemo/stdint.h>
#include <nemo/error.h>
#include <nemo/byte.h>
#include <nemo/ip4.h>
#include <nemo/char.h>

#include "dns.h"
#include "printrecord.h"
#include "safe.h"

#include <nemo/uint16.h>
#include <nemo/uint32.h>

static dns_domain dname = DNS_DOMAIN;

static stralloc tmp = STRALLOC;
static stralloc tmp2 = STRALLOC;

static const char SPACE[] = " ";
static const char DOT[] = ".";
static const char QUOTE[] = "\"";
static const char COLON[] = ":";

static unsigned int printable(byte_t ch)
{
  if (ch == '.') return 1;
  if ((ch >= 'a') && (ch <= 'z')) return 1;
  if ((ch >= '0') && (ch <= '9')) return 1;
  if ((ch >= 'A') && (ch <= 'Z')) return 1;
  if (ch == ':') return 1;
  if (ch == '/') return 1;
  if (ch == '-') return 1;
  if (ch == '_') return 1;
  if (ch == ' ') return 1;
  if (ch == '=') return 1;
  return 0;
}

static unsigned int append_type(stralloc *out, unsigned int type)
{
  register const char *x;

  if (!stralloc_append(out, SPACE)) return 0;
  x = dns_type_str(type);
  if (x) {
    if (!stralloc_cats(out, x)) return 0;
  }
  else {
    if (!stralloc_catulong0(out, type, 0)) return 0;
  }
  return 1;
}

static unsigned int append_degrees(stralloc *out, uint32_t value, const char *s1, const char *s2)
{
  uint32_t relative_value;
  uint32_t thousandths;
  uint32_t seconds;
  uint32_t minutes;
  uint32_t degrees;
  unsigned int flag_positive;

  if (!stralloc_append(out, SPACE)) return 0;
  flag_positive = value >= 0x80000000;
  relative_value = (flag_positive) ? value - 0x80000000 : 0x80000000 - value;
  thousandths = relative_value % 1000;
  relative_value /= 1000;
  seconds = relative_value % 60;
  relative_value /= 60;
  minutes = relative_value % 60;
  relative_value /= 60;
  degrees = relative_value;
  if (!stralloc_catulong0(out, degrees, 0)) return 0;
  if (!stralloc_append(out, COLON)) return 0;
  if (!stralloc_catulong0(out, minutes, 2)) return 0;
  if (!stralloc_append(out, COLON)) return 0;
  if (!stralloc_catulong0(out, seconds, 2)) return 0;
  if (!stralloc_append(out, DOT)) return 0;
  if (!stralloc_catulong0(out, thousandths, 3)) return 0;
  if (!stralloc_append(out, (flag_positive) ? s1 : s2)) return 0;
  return 1;
}

static unsigned int poweroften[10] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

static unsigned int append_size(stralloc *out, unsigned int precision)
{
  unsigned int mantissa;
  unsigned int exponent;
  unsigned int size;  /* cm */

  if (!stralloc_append(out, SPACE)) return 0;
  if (!stralloc_cats(out, "+/-")) return 0;
  mantissa = precision >> 4;
  exponent = precision & 0x0f;
  if (exponent > 9) {
    exponent = 9;
  }
  size = mantissa * poweroften[exponent];
  size >>= 1;
  if (!stralloc_catulong0(out, size / 100, 0)) return 0;
  if (!stralloc_append(out, DOT)) return 0;
  if (!stralloc_catulong0(out, size % 100, 2)) return 0;
  if (!stralloc_append(out, "m")) return 0;
  return 1;
}

unsigned int printrecord_cat(const byte_t *buf, unsigned int len, unsigned int pos, const dns_domain *qname, const dns_type *qtype, stralloc *out)
{
  char str[IP6_FMT];
  byte_t misc[256];
  dns_type type;
  dns_class class;
  ip4_address ip4;
  ip6_address ip6;
  uint16_t datalen;
  uint16_t u16tmp;
  uint16_t u16;
  uint32_t u32;
  unsigned int itype;
  unsigned int oldpos;
  unsigned int newpos;
  unsigned int i;
  byte_t ch;
  byte_t loc_size;
  byte_t loc_hp;
  byte_t loc_vp;

  pos = safe_packet_getname(buf, len, pos, &dname);
  if (!pos) return 0;
  pos = dns_packet_copy(buf, len, pos, misc, 10);
  if (!pos) return 0;
  dns_type_unpack(&type, misc);
  dns_class_unpack(&class, misc + 2);
  uint16_unpack_big(&datalen, misc + 8);
  newpos = pos + datalen;

  if (qname) {
    if (!dns_domain_equal(&dname, qname)) {
      return newpos;
    }
    if (dns_type_diff(qtype, &type) && dns_type_diff(qtype, dns_t_any)) {
      return newpos;
    }
  }

  if (!dns_domain_todot_cat(&dname, out)) return 0;

  if (!stralloc_append(out, SPACE)) return 0;
  uint32_unpack_big(&u32, misc + 4);
  if (!stralloc_catulong0(out, u32, 0)) return 0;

  if (dns_class_diff(&class, dns_c_in)) {
    if (!stralloc_cats(out, " weird class\n")) return 0;
    return newpos;
  }

  itype = dns_type_get(&type);
  if (!append_type(out, itype)) return 0;

  if (!stralloc_append(out, SPACE)) return 0;
  switch (itype) {
    case DNS_T_NS:
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      break;

    case DNS_T_PTR:
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      break;

    case DNS_T_CNAME:
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      break;

    case DNS_T_MX:
      pos = dns_packet_copy(buf, len, pos, misc, 2);
      if (!pos) return 0;
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      uint16_unpack_big(&u16, misc);
      if (!stralloc_catulong0(out, u16, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      break;

    case DNS_T_SOA:
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, 20);
      if (!pos) return 0;
      for (i = 0; i < 5; ++i) {
        if (!stralloc_append(out, SPACE)) return 0;
        uint32_unpack_big(&u32, misc + 4 * i);
        if (!stralloc_catulong0(out, u32, 0)) return 0;
      }
      break;

    case DNS_T_A:
      if (datalen != 4) {
        errno = error_proto;
        return 0;
      }
      pos = dns_packet_copy(buf, len, pos, misc, 4);
      if (!pos) return 0;
      ip4_unpack(&ip4, misc);
      str[ip4_fmt(&ip4, str)] = '\0';
      if (!stralloc_cats(out, str)) return 0;
      break;

    case DNS_T_AAAA:
      if (datalen != 16) {
        errno = error_proto;
        return 0;
      }
      pos = dns_packet_copy(buf, len, pos, misc, 16);
      if (!pos) return 0;
      ip6_unpack(&ip6, misc);
      str[ip6_fmt(&ip6, str)] = '\0';
      if (!stralloc_cats(out, str)) return 0;
      break;

    case DNS_T_CAA:
      pos = dns_packet_copy(buf, len, pos, &ch, 1);
      if (!pos) return 0;
      datalen--;
      if (!stralloc_catulong0(out, ch, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, &ch, 1);
      if (!pos) return 0;
      datalen--;
      i = ch;
      if (i > 15) return 0;  /* tag length */
      pos = dns_packet_copy(buf, len, pos, misc, i);
      if (!stralloc_catb(out, misc, i)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      datalen = (uint16_t)(datalen - i);
      pos = dns_packet_copy(buf, len, pos, misc, datalen);
      if (!pos) return 0;
      if (!stralloc_catb(out, misc, datalen)) return 0;
      break;

    case DNS_T_DNSKEY:
      pos = dns_packet_copy(buf, len, pos, misc, 2);  /* flags */
      if (!pos) return 0;
      datalen--;
      datalen--;
      uint16_unpack_big(&u16, misc);
      if (!stralloc_catulong0(out, u16, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, &ch, 1);  /* protocol */
      if (!pos) return 0;
      datalen--;
      if (!stralloc_catulong0(out, ch, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, &ch, 1);  /* algorithm */
      if (!pos) return 0;
      datalen--;
      if (!stralloc_catulong0(out, ch, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      if (!stralloc_erase(&tmp)) return 0;
      while (datalen--) {
        pos = dns_packet_copy(buf, len, pos, &ch, 1);
        if (!pos) return 0;
        if (!stralloc_append(&tmp, &ch)) return 0;
      }
      if (!stralloc_base64_encode(&tmp2, &tmp)) return 0;
      if (!stralloc_cat(out, &tmp2)) return 0;
      break;

    case DNS_T_SRV:
      pos = dns_packet_copy(buf, len, pos, misc, 2);
      if (!pos) return 0;
      uint16_unpack_big(&u16tmp, misc);
      pos = dns_packet_copy(buf, len, pos, misc, 2);
      if (!pos) return 0;
      uint16_unpack_big(&u16, misc);
      if (!stralloc_catulong0(out, u16, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      if (!stralloc_catulong0(out, u16tmp, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, 2);
      if (!pos) return 0;
      uint16_unpack_big(&u16, misc);
      if (!stralloc_catulong0(out, u16, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      break;

    case DNS_T_NAPTR:
      pos = dns_packet_copy(buf, len, pos, misc, 2);
      if (!pos) return 0;
      uint16_unpack_big(&u16, misc);
      if (!stralloc_catulong0(out, u16, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, 2);
      if (!pos) return 0;
      uint16_unpack_big(&u16, misc);
      if (!stralloc_catulong0(out, u16, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, &ch, 1);
      if (!pos) return 0;
      pos = dns_packet_copy(buf,len, pos, misc, ch);
      if (!pos) return 0;
      if (!stralloc_append(out, QUOTE)) return 0;
      if (!stralloc_catb(out, misc, ch)) return 0;
      if (!stralloc_append(out, QUOTE)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, &ch, 1);
      if (!pos) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, ch);
      if (!pos) return 0;
      if (!stralloc_append(out, QUOTE)) return 0;
      if (!stralloc_catb(out, misc, ch)) return 0;
      if (!stralloc_append(out, QUOTE)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, &ch, 1);
      if (!pos) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, ch);
      if (!pos) return 0;
      if (!stralloc_append(out, QUOTE)) return 0;
      if (!stralloc_catb(out, misc, ch)) return 0;
      if (!stralloc_append(out, QUOTE)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = safe_packet_getname(buf, len, pos, &dname);
      if (!pos) return 0;
      oldpos = out->len;
      if (!dns_domain_todot_cat(&dname, out)) return 0;
      if (out->len == oldpos) {
        if (!stralloc_append(out, DOT)) return 0;
      }
      break;

    case DNS_T_TXT:
      i = 0;
      while (datalen--) {
	pos = dns_packet_copy(buf, len, pos, &ch, 1);
	if (!pos) return 0;
	if (!i) {
          i = (byte_t)ch;  /* char str len */
          continue;
	}
	i--;
	if (printable(ch) && (ch != '\\')) {
	  if (!stralloc_append(out, &ch)) return 0;
	}
	else {
	  misc[3] = (byte_t)char_hex_chars[7 & ch];
	  ch >>= 3;
	  misc[2] = (byte_t)char_hex_chars[7 & ch];
	  ch >>= 3;
	  misc[1] = (byte_t)char_hex_chars[7 & ch];
	  misc[0] = '\\';
	  if (!stralloc_catb(out, misc, 4)) return 0;
	}
      }
      break;

    case DNS_T_SPF:
      i = 0;
      while (datalen--) {
	pos = dns_packet_copy(buf, len, pos, &ch, 1);
	if (!pos) return 0;
	if (!i) {
          i = (byte_t)ch;  /* char str len */
          continue;
	}
	i--;
	if (printable(ch) && (ch != '\\')) {
	  if (!stralloc_append(out, &ch)) return 0;
	}
	else {
	  misc[3] = (byte_t)char_hex_chars[7 & ch];
	  ch >>= 3;
	  misc[2] = (byte_t)char_hex_chars[7 & ch];
	  ch >>= 3;
	  misc[1] = (byte_t)char_hex_chars[7 & ch];
	  misc[0] = '\\';
	  if (!stralloc_catb(out, misc, 4)) return 0;
	}
      }
      break;

    case DNS_T_LOC:
      pos = dns_packet_copy(buf, len, pos, &ch, 1);  /* version */
      if (!pos) return 0;
      if (!stralloc_append(out, "v")) return 0;
      if (!stralloc_catulong0(out, ch, 0)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, &loc_size, 1);  /* size */
      if (!pos) return 0;
      pos = dns_packet_copy(buf, len, pos, &loc_hp, 1);  /* horiz pre */
      if (!pos) return 0;
      pos = dns_packet_copy(buf, len, pos, &loc_vp, 1);  /* vert pre */
      if (!pos) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, 4);  /* latitude */
      if (!pos) return 0;
      uint32_unpack_big(&u32, misc);
      if (!append_degrees(out, u32, "N", "S")) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, 4);  /* longitude */
      if (!pos) return 0;
      uint32_unpack_big(&u32, misc);
      if (!append_degrees(out, u32, "E", "W")) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      pos = dns_packet_copy(buf, len, pos, misc, 4);  /* altitude - ignore */
      if (!pos) return 0;
      if (!append_size(out, loc_size)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      if (!append_size(out, loc_hp)) return 0;
      if (!stralloc_append(out, SPACE)) return 0;
      if (!append_size(out, loc_vp)) return 0;
      break;

    default:
      while (datalen--) {
        pos = dns_packet_copy(buf, len, pos, &ch, 1);
        if (!pos) return 0;
        if (printable(ch) && (ch != '\\')) {
          if (!stralloc_catb(out, &ch, 1)) return 0;
        }
        else {
          misc[3] = (byte_t)char_hex_chars[7 & ch];
          ch >>= 3;
          misc[2] = (byte_t)char_hex_chars[7 & ch];
          ch >>= 3;
          misc[1] = (byte_t)char_hex_chars[7 & ch];
          misc[0] = '\\';
          if (!stralloc_catb(out, misc, 4)) return 0;
        }
      }
      break;
  }

  if (!stralloc_append(out, "\n")) return 0;
  if (pos != newpos) {
    errno = error_proto;
    return 0;
  }
  return newpos;
}

unsigned int printrecord(const byte_t *buf, unsigned int len, unsigned int pos, const dns_domain *qname, const dns_type *qtype, stralloc *out)
{
  if (!stralloc_erase(out)) return 0;
  return printrecord_cat(buf, len, pos, qname, qtype, out);
}
