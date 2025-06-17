#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>
#include <nemo/exit.h>
#include <nemo/scan.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/getln.h>
#include <nemo/cdb_make.h>
#include <nemo/open.h>
#include <nemo/unix.h>
#include <nemo/char.h>
#include <nemo/uint16.h>
#include <nemo/uint32.h>
#include <nemo/uint64.h>
#include <nemo/error.h>
#include <nemo/uint_vector.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "die.h"
#include "whitespace.h"

#include <sys/param.h>
#include <netdb.h>
#include <sys/stat.h>

#define TTL_NS 259200
#define TTL_POSITIVE 86400
#define TTL_NEGATIVE 2560

static const char LONG_LABEL_MSG[] = "label length exceeds 255 bytes";

static stralloc empty = STRALLOC;
static stralloc tmp = STRALLOC;

static unsigned int line_num = 0;

static byte_t default_soa[20];
static uint32_t default_serial = 0;
static uint32_t default_refresh_time = DNS_SOA_REFRESH_TIME_DEFAULT;
static uint32_t default_retry_time = DNS_SOA_RETRY_TIME_DEFAULT;
static uint32_t default_expire_time = DNS_SOA_EXPIRE_TIME_DEFAULT;
static uint32_t default_minimum_time = DNS_SOA_MINIMUM_TIME_DEFAULT;

static djbio data_in;
static byte_t bspace[1024];

static stralloc line = STRALLOC;

static stralloc verb = STRALLOC;

static sa_vector fields = SA_VECTOR;
static stralloc *f;

static int fd_cdb;
static struct cdb_make cdb;
static stralloc key = STRALLOC;
static stralloc result = STRALLOC;

static dns_domain d1 = DNS_DOMAIN;

static uint_vector type_list = UINT_VECTOR;

static void die_datatmp(void)
{
  die_create("data.cdb.tmp");
}

static void die_field_missing(const char *what)
{
  static stralloc message = STRALLOC;

  if (!stralloc_copys(&message, "missing ")) die_nomem();
  if (!stralloc_cats(&message, what)) die_nomem();
  if (!stralloc_0(&message)) die_nomem();
  die_syntax(line_num, message.s);
}

static void die_syntax_malformed(const char *what, const stralloc *sa)
{
  static stralloc message = STRALLOC;

  if (!stralloc_copys(&message, "malformed ")) die_nomem();
  if (!stralloc_cats(&message, what)) die_nomem();
  if (!stralloc_cats(&message, ": ")) die_nomem();
  if (!stralloc_cat(&message, sa)) die_nomem();
  if (!stralloc_0(&message)) die_nomem();
  die_syntax(line_num, message.s);
}

static void die_syntax_error(const char *what, const stralloc *sa)
{
  static stralloc message = STRALLOC;

  if (!stralloc_copys(&message, what)) die_nomem();
  if (!stralloc_cats(&message, ": ")) die_nomem();
  if (!stralloc_cat(&message, sa)) die_nomem();
  if (!stralloc_0(&message)) die_nomem();
  die_syntax(line_num, message.s);
}

static void die_type_prohibited(const stralloc *what)
{
  static stralloc message = STRALLOC;

  if (!stralloc_copys(&message, "type ")) die_nomem();
  if (!stralloc_cat(&message, what)) die_nomem();
  if (!stralloc_cats(&message, " prohibited")) die_nomem();
  if (!stralloc_0(&message)) die_nomem();
  die_syntax(line_num, message.s);
}

static void pad_fields(unsigned int required, sa_vector *v)
{
  while (v->len < required) {
    if (!sa_vector_append(v, &empty)) die_nomem();
  }
}

static unsigned int ttl_parse(const stralloc *sa, unsigned int def)
{
  unsigned int len;
  unsigned int ttl;
  if (!sa->len) return def;
  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  len = scan_uint(tmp.s, &ttl);
  if (tmp.s[len]) die_syntax_malformed("TTL", sa);
  return ttl;
}

static unsigned int ip_parse(const stralloc *sa, ip4_address *ip4, ip6_address *ip6)
{
  unsigned int len;
  if (!sa->len) return 0;
  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  len = ip4_scan(ip4, tmp.s);
  if (!tmp.s[len]) return 4;
  len = ip6_scanbracket(ip6, tmp.s);
  if (!tmp.s[len]) return 6;
  die_syntax_malformed("IPv4/IPv6 address", sa);
  return 0;
}

static unsigned int uint_parse(const stralloc *sa, unsigned int def, const char *errmsg)
{
  unsigned int len;
  unsigned int u;

  if (!sa->len) return def;
  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  len = scan_uint(tmp.s, &u);
  if (tmp.s[len]) die_syntax_malformed(errmsg, sa);
  return u;
}

static uint64_t ttd_parse(const stralloc *sa)
{
  uint64_t ttd;
  unsigned int i;
  byte_t ch;

  if (sa->len > 16) die_syntax_error("oversized timestamp", sa);
  ttd = 0;
  for (i = 0; i < sa->len; ++i) {
    ch = char_hex_table[(byte_t)sa->s[i]];
    if (ch > 15) die_syntax_malformed("timestamp", sa);
    ttd <<= 4;
    ttd |= (uint64_t)ch;
  }
  return ttd;
}

static unsigned int type_parse(const stralloc *sa)
{
  dns_type type;

  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (!dns_type_parse(&type, tmp.s)) die_syntax_malformed("type", sa);
  return dns_type_get(&type);
}

static unsigned int port_parse(const stralloc *sa)
{
  struct servent *se;
  unsigned int len;
  unsigned int u;

  if (!sa->len) die_field_missing("port name/number");
  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  len = scan_uint(tmp.s, &u);
  if (!tmp.s[len]) return u;
  se = getservbyname(tmp.s, 0);
  if (!se) die_syntax_malformed("port name/number", sa);
  return ntohs((uint16_t)se->s_port);
}

static unsigned int security_algorithm_parse(stralloc *sa)
{
  unsigned int u;

  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (!tmp.s[scan_uint(tmp.s, &u)]) return u;

  stralloc_upper(sa);
  if (stralloc_equals(sa, "RSA/MD5")) return 1;
  if (stralloc_equals(sa, "RSAMD5")) return 1;
  if (stralloc_equals(sa, "DH")) return 2;
  if (stralloc_equals(sa, "DSA/SHA-1")) return 3;
  if (stralloc_equals(sa, "DSA")) return 3;
  if (stralloc_equals(sa, "ECC")) return 4;
  if (stralloc_equals(sa, "RSA/SHA-1")) return 5;
  if (stralloc_equals(sa, "RSASHA1")) return 5;
  if (stralloc_equals(sa, "DSA-NSEC3-SHA1")) return 6;
  if (stralloc_equals(sa, "RSASHA1-NSEC3-SHA1")) return 7;
  if (stralloc_equals(sa, "RSA/SHA-256")) return 8;
  if (stralloc_equals(sa, "RSASHA256")) return 8;
  if (stralloc_equals(sa, "RSA/SHA-512")) return 10;
  if (stralloc_equals(sa, "RSASHA512")) return 10;
  if (stralloc_equals(sa, "ECC-GOST")) return 12;
  if (stralloc_equals(sa, "ECDSAP256SHA256")) return 13;
  if (stralloc_equals(sa, "ECDSAP384SHA384")) return 14;
  if (stralloc_equals(sa, "ED25519")) return 15;
  if (stralloc_equals(sa, "ED448")) return 16;
  if (stralloc_equals(sa, "INDIRECT")) return 252;
  if (stralloc_equals(sa, "PRIVATEDNS")) return 253;
  if (stralloc_equals(sa, "PRIVATEOID")) return 254;

  die_syntax_malformed("security algorithm", sa);
  return 0;
}

static unsigned int dnssec_digest_type_parse(stralloc *sa)
{
  unsigned int u;

  if (!stralloc_copy(&tmp, sa)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (!tmp.s[scan_uint(tmp.s, &u)]) return u;

  stralloc_upper(sa);
  if (stralloc_equals(sa, "SHA-1")) return 1;
  if (stralloc_equals(sa, "SHA1")) return 1;
  if (stralloc_equals(sa, "SHA-256")) return 2;
  if (stralloc_equals(sa, "SHA256")) return 2;
  if (stralloc_equals(sa, "GOST")) return 3;
  if (stralloc_equals(sa, "SHA-384")) return 4;
  if (stralloc_equals(sa, "SHA384")) return 4;

  die_syntax_malformed("DNSSEC digest type", sa);
  return 0;
}


static void hex_parse(const stralloc *in, stralloc *out)
{
  if (!stralloc_hex_decode(out, in)) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_syntax_malformed("HEX data", in);
    die_internal();
  }
}

static void base64_parse(const stralloc *in, stralloc *out)
{
  if (!stralloc_base64_decode(out, in)) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_syntax_malformed("Base64 data", in);
    die_internal();
  }
}

static void loc_parse(const stralloc *sa, byte_t loc[2])
{
  loc[0] = (byte_t)((sa->len > 0) ? sa->s[0] : '\0');
  loc[1] = (byte_t)((sa->len > 1) ? sa->s[1] : '\0');
}

static unsigned int ip4mask_parse(ip4_address *ip, stralloc *in)
{
  unsigned int m;

  if (!in->len) return 0;
  if (!stralloc_copy(&tmp, in)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (!ip4_mask_scan(ip, &m, tmp.s)) die_syntax_malformed("IPv4 prefix", in);
  if (m & 7) die_syntax_error("IPv4 mask not 8 bit aligned", in);
  if (!m) die_syntax_error("IPv4 mask too small", in);
  return m;
}

static unsigned int ip6mask_parse(ip6_address *ip, stralloc *in)
{
  unsigned int m;

  if (!in->len) return 0;
  if (!stralloc_copy(&tmp, in)) die_nomem();
  if (!stralloc_0(&tmp)) die_nomem();
  if (!ip6_mask_scanbracket(ip, &m, tmp.s)) die_syntax_malformed("IPv6 prefix", in);
  if (m & 7) die_syntax_error("IPv6 mask not 8 bit aligned", in);
  if (!m) die_syntax_error("IPv6 mask too small", in);
  return m;
}

static void txt_parse(stralloc *sa)
{
  unsigned int i;
  unsigned int j;
  char ch;

  j = i = 0;
  while (i < sa->len) {
    ch = sa->s[i++];
    if (ch == '\\') {
      if (i >= sa->len) break;
      ch = sa->s[i++];
      if ((ch >= '0') && (ch <= '7')) {
        ch = (char)(ch - '0');
        if ((i < sa->len) && (sa->s[i] >= '0') && (sa->s[i] <= '7')) {
          ch = (char)(ch << 3);
          ch = (char)(ch + sa->s[i++] - '0');
          if ((i < sa->len) && (sa->s[i] >= '0') && (sa->s[i] <= '7')) {
            ch = (char)(ch << 3);
            ch = (char)(ch + sa->s[i++] - '0');
          }
        }
      }
    }
    sa->s[j++] = ch;
  }
  sa->len = j;
}

static void domain_parse(dns_domain *d, const stralloc *sa)
{
  if (!dns_domain_fromdot(d, sa->s, sa->len)) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_syntax_malformed("FQDN", sa);
    die_internal();
  }
}

static void default_soa_init(int fd)
{
  struct stat st;

  if (fstat(fd, &st) < 0) die_stat("data");

  default_serial = (uint32_t)st.st_mtime;
  if (!default_serial) {
    default_serial = 1;
  }
  uint32_pack_big(default_serial, default_soa);
  uint32_pack_big(default_refresh_time, default_soa + 4);
  uint32_pack_big(default_retry_time, default_soa + 8);
  uint32_pack_big(default_expire_time, default_soa + 12);
  uint32_pack_big(default_minimum_time, default_soa + 16);
}

static void rr_add(const void *buf, unsigned int len)
{
  if (!stralloc_catb(&result, buf, len)) die_nomem();
}

static void rr_add_name(const dns_domain *d)
{
  rr_add(d->data, d->len);
}

static void rr_add_ip4(const ip4_address *ip)
{
  rr_add(ip->d, 4);
}

static void rr_add_ip6(const ip6_address *ip)
{
  rr_add(ip->d, 16);
}

static unsigned int rr_add_len(unsigned int len)
{
  byte_t ch;

  if (len > 255) {
    len = 255;
  }
  ch = (byte_t)len;
  rr_add(&ch, 1);
  return len;
}

static void rr_add_txt(const stralloc *sa)
{
  unsigned int i;
  unsigned int k;

  i = 0;
  while (i < sa->len) {
    k = rr_add_len(sa->len - i);
    rr_add(sa->s + i, k);
    i += k;
  }
}

static void rr_add_string(const stralloc *sa)
{
  unsigned int k;

  k = rr_add_len(sa->len);
  rr_add(sa->s, k);
}

static void rr_add_uint8(unsigned int u)
{
  byte_t ch;

  ch = (byte_t)u;
  rr_add(&ch, 1);
}

static void rr_add_uint16(unsigned int u)
{
  byte_t buf[sizeof(uint16_t)];

  uint16_pack_big((uint16_t)u, buf);
  rr_add(buf, sizeof(buf));
}

static void rr_add_uint32(unsigned int u)
{
  byte_t buf[sizeof(uint32_t)];

  uint32_pack_big((uint32_t)u, buf);
  rr_add(buf, sizeof(buf));
}

static void rr_add_uint64(uint64_t u)
{
  byte_t buf[sizeof(uint64_t)];

  uint64_pack_big(u, buf);
  rr_add(buf, sizeof(buf));
}

static void rr_add_nsec_window_block(byte_t *data, unsigned int window)
{
  byte_t ch;
  unsigned int i;
  unsigned int len;

  ch = (byte_t)window;
  rr_add(&ch, 1);
  len = 32;
  for (i = 0; i < 32; i++) {
    if (data[i]) {
      len = i;
    }
  }
  if (len == 32) return;  /* oops */
  len++;  /* convert from index to length */
  ch = (byte_t)len;
  rr_add(&ch, 1);
  rr_add(data, len);
}

static void nsec_map_type(unsigned int lsb, byte_t *map)
{
  unsigned int i;
  unsigned int shift;

  i = lsb >> 3;
  shift = lsb & 0x07;
  map[i] = (byte_t)(map[i] | 1 << shift);
}

static void rr_add_nsec_type_bits_map(void)
{
  byte_t data[32];
  unsigned int i;
  unsigned int t;
  unsigned int last_msb;
  unsigned int msb;
  unsigned int lsb;

  last_msb = 0;
  byte_zero(data, sizeof(data));
  uint_vector_sort(&type_list);
  for (i = 0; i < type_list.len; ++i) {
    t = type_list.va[i];
    msb = t >> 8;
    lsb = t & 0xff;
    if (msb != last_msb) {
      rr_add_nsec_window_block(data, msb);
      byte_zero(data, sizeof(data));
      msb = last_msb;
    }
    nsec_map_type(lsb, data);
  }
}

static void rr_start(const dns_type *type, unsigned int ttl, uint64_t ttd, const byte_t loc[2])
{
  byte_t buf[4];

  dns_type_pack(type, buf);
  if (!stralloc_copyb(&result, buf, 2)) die_nomem();
  if (byte_equal(loc, 2, "\0\0")) {
    rr_add("=", 1);
  }
  else {
    rr_add(">", 1);  /* '=' + 1 */
    rr_add(loc, 2);
  }
  rr_add_uint32(ttl);
  rr_add_uint64(ttd);
}

static void rr_finish(const dns_domain *owner)
{
  static dns_domain d = DNS_DOMAIN;

  if (!dns_domain_copy(&d, owner)) die_nomem();
  if (byte_equal(d.data, 2, "\1*")) {
    dns_domain_drop1label(&d);  /* drop wildcard */
    result.s[2] = (char)(result.s[2] - 19);
  }
  if (!stralloc_copyb(&key, d.data, d.len)) die_nomem();
  stralloc_lower(&key);
  if (cdb_make_add(&cdb, key.s, key.len, result.s, result.len) < 0) {
    die_datatmp();
  }
}

int main(int argc __UNUSED__, char **argv)
{
  static dns_domain fqdn = DNS_DOMAIN;

  unsigned int match;
  unsigned int i;
  unsigned int u;
  unsigned int ttl;
  uint64_t ttd;
  byte_t loc[2];
  ip4_address ip4;
  ip6_address ip6;
  dns_type type;
  int fd_data;

  PROGRAM = *argv;
  umask(022);

  if (!stralloc_erase(&empty)) die_nomem();

  fd_data = open_read("data");
  if (fd_data < 0) die_open("data");
  default_soa_init(fd_data);

  djbio_initread(&data_in, read, fd_data, bspace, sizeof bspace);

  fd_cdb = open_trunc("data.cdb.tmp");
  if (fd_cdb < 0) die_datatmp();
  if (cdb_make_start(&cdb, fd_cdb) < 0) die_datatmp();

  match = 1;
  while (match) {
    ++line_num;
    if (getln(&data_in, &line, &match, '\n') < 0) die_read_line(line_num);

    stralloc_trim(&line, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!line.len) continue;
    if (line.s[0] == '#') continue;
    if (line.s[0] == '-') continue;

    if (!sa_vector_parse_config(&fields, &line)) {
      if (errno == error_proto) die_syntax_error("malformed field (octal or IPv6)", &line);
      if (errno == error_nomem) die_nomem();
      die_internal();
    }
    if (fields.len < 2) die_syntax_error("insufficient fields", &line);
    if (!stralloc_copy(&verb, &fields.va[0])) die_nomem();
    stralloc_upper(&verb);
    sa_vector_remove(&fields, 0, 1);  /* remove verb */
    f = fields.va;

    if (stralloc_equals(&verb, "%")) {  /* location code */
      pad_fields(3, &fields);
      loc_parse(&f[0], loc);
      u = ip4mask_parse(&ip4, &f[1]);
      if (u) {
        if (!stralloc_copyb(&key, "\0%4\0", 4)) die_nomem();
        if (!stralloc_catb(&key, ip4.d, u >> 3)) die_nomem();
        if (cdb_make_add(&cdb, key.s, key.len, loc, 2) < 0) die_datatmp();
      }
      u = ip6mask_parse(&ip6, &f[2]);
      if (u) {
        if (!stralloc_copyb(&key, "\0%6\0", 4)) die_nomem();
        if (!stralloc_catb(&key, ip6.d, u >> 3)) die_nomem();
        if (cdb_make_add(&cdb, key.s, key.len, loc, 2) < 0) die_datatmp();
      }
      if (!f[1].len && !f[2].len) {
        if (!stralloc_copyb(&key, "\0%4\0", 4)) die_nomem();
        if (cdb_make_add(&cdb, key.s, key.len, loc, 2) < 0) die_datatmp();
        if (!stralloc_copyb(&key, "\0%6\0", 4)) die_nomem();
        if (cdb_make_add(&cdb, key.s, key.len, loc, 2) < 0) die_datatmp();
      }
      continue;
    }

    pad_fields(4, &fields);
    if (!f[0].len) die_field_missing("FQDN");
    domain_parse(&fqdn, &f[0]);
    ttd = ttd_parse(&f[2]);
    loc_parse(&f[3], loc);

    if (stralloc_equals(&verb, "SOA")) {  /* DNS_T_SOA */
      ttl = ttl_parse(&f[1], DNS_SOA_TTL_DEFAULT);
      pad_fields(11, &fields);
      rr_start(dns_t_soa, ttl, ttd, loc);
      domain_parse(&d1, &f[4]);
      rr_add_name(&d1);
      domain_parse(&d1, &f[5]);
      rr_add_name(&d1);
      rr_add_uint32(uint_parse(&f[6], default_serial, "serial"));
      rr_add_uint32(uint_parse(&f[7], default_refresh_time, "refresh time"));
      rr_add_uint32(uint_parse(&f[8], default_retry_time, "retry time"));
      rr_add_uint32(uint_parse(&f[9], default_expire_time, "expire time"));
      rr_add_uint32(uint_parse(&f[10], default_minimum_time, "minimum time"));
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "&") || stralloc_equals(&verb, ".")) {
      /* &  --> DNS_T_NS[,DNS_T_A/DNS_T_AAAA] */
      /* .  --> DNS_T_NS[,DNS_T_A/DNS_T_AAAA],DNS_T_SOA */
      pad_fields(5, &fields);
      if (!f[4].len) die_field_missing("name server name");
      if (stralloc_chr(&f[4], '.') == f[4].len) {
        if (!stralloc_catb(&f[4], ".ns.", 4)) die_nomem();
        if (!stralloc_cat(&f[4], &f[0])) die_nomem();
      }
      domain_parse(&d1, &f[4]);
      if (stralloc_equals(&verb, ".")) {
        ttl = ttl_parse(&f[1], TTL_NEGATIVE);
        rr_start(dns_t_soa, ttl, ttd, loc);
        rr_add_name(&d1);
        rr_add("\012hostmaster", 11);
        rr_add_name(&fqdn);
        rr_add(default_soa, 20);
        rr_finish(&fqdn);
      }
      ttl = ttl_parse(&f[1], TTL_NS);
      rr_start(dns_t_ns, ttl, ttd, loc);
      rr_add_name(&d1);
      rr_finish(&fqdn);
      for (i = 5; i < fields.len; i++) {
	switch (ip_parse(&f[i], &ip4, &ip6)) {
	  case 4:
	    rr_start(dns_t_a, ttl, ttd, loc);
	    rr_add_ip4(&ip4);
	    rr_finish(&d1);
	    break;
	  case 6:
	    rr_start(dns_t_aaaa, ttl, ttd, loc);
	    rr_add_ip6(&ip6);
	    rr_finish(&d1);
	    break;
	  default:
	    break;
	}
      }
      continue;
    }

    ttl = ttl_parse(&f[1], TTL_POSITIVE);

    if (stralloc_equals(&verb, "+") || stralloc_equals(&verb, "=")) {
      /* + --> DNS_T_A/DNS_T_AAAA */
      /* = --> DNS_T_A/DNS_T_AAAA, DNS_T_PTR */
      pad_fields(4, &fields);
      for (i = 4; i < fields.len; i++) {
	switch (ip_parse(&f[i], &ip4, &ip6)) {
	  case 4:
	    rr_start(dns_t_a, ttl, ttd, loc);
	    rr_add_ip4(&ip4);
	    rr_finish(&fqdn);
	    if (stralloc_equals(&verb, "=")) {
	      dns_name4_domain(&d1, &ip4);
	      rr_start(dns_t_ptr, ttl, ttd, loc);
	      rr_add_name(&fqdn);
	      rr_finish(&d1);
	    }
	    break;
	  case 6:
	    rr_start(dns_t_aaaa, ttl, ttd, loc);
	    rr_add_ip6(&ip6);
	    rr_finish(&fqdn);
	    if (stralloc_equals(&verb, "=")) {
	      dns_name6_domain(&d1, &ip6);
	      rr_start(dns_t_ptr, ttl, ttd, loc);
	      rr_add_name(&fqdn);
	      rr_finish(&d1);
	    }
	    break;
	  default:
	    die_field_missing("IP address");
	    break;
	}
      }
      continue;
    }

    if (stralloc_equals(&verb, "@")) {  /* DNS_T_MX[,DNS_T_A/DNS_T_AAAA] */
      pad_fields(6, &fields);
      rr_start(dns_t_mx, ttl, ttd, loc);
      rr_add_uint16(uint_parse(&f[4], 0, "MX distance"));
      if (!f[5].len) die_field_missing("mail exchange server");
      if (stralloc_chr(&f[5], '.') == f[2].len) {
        if (!stralloc_cats(&f[5], ".mx.")) die_nomem();
        if (!stralloc_cat(&f[5], &f[0])) die_nomem();
      }
      domain_parse(&d1, &f[5]);
      rr_add_name(&d1);
      rr_finish(&fqdn);
      for (i = 6; i < fields.len; i++) {
	switch (ip_parse(&f[i], &ip4, &ip6)) {
	  case 4:
	    rr_start(dns_t_a, ttl, ttd, loc);
	    rr_add_ip4(&ip4);
	    rr_finish(&d1);
	    break;
	  case 6:
	    rr_start(dns_t_aaaa, ttl, ttd, loc);
	    rr_add_ip6(&ip6);
	    rr_finish(&d1);
	    break;
	  default:
	    die_field_missing("IP address");
	    break;
	}
      }
      continue;
    }

    if (stralloc_equals(&verb, "^")) {  /* DNS_T_PTR */
      pad_fields(5, &fields);
      rr_start(dns_t_ptr, ttl, ttd, loc);
      if (!f[4].len) die_field_missing("target name");
      domain_parse(&d1, &f[4]);
      rr_add_name(&d1);
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "'")) {  /* DNS_T_TXT */
      pad_fields(5, &fields);
      if (!f[4].len) die_field_missing("text segment");
      rr_start(dns_t_txt, ttl, ttd, loc);
      for (i = 4; i < fields.len; i++) {
        txt_parse(&f[i]);
        rr_add_txt(&f[i]);
      }
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "CNAME")) {  /* DNS_T_CNAME */
      pad_fields(5, &fields);
      rr_start(dns_t_cname, ttl, ttd, loc);
      if (!f[4].len) die_field_missing("target name");
      domain_parse(&d1, &f[4]);
      rr_add_name(&d1);
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "SRV")) {  /* DNS_T_SRV */
      pad_fields(8, &fields);
      rr_start(dns_t_srv, ttl, ttd, loc);
      rr_add_uint16(uint_parse(&f[4], 0, "weight"));
      rr_add_uint16(uint_parse(&f[5], 0, "priority"));
      rr_add_uint16(port_parse(&f[6]));
      if (!f[7].len) die_field_missing("server name");
      if (stralloc_chr(&f[7], '.') == f[7].len) {
        if (!stralloc_cats(&f[7], ".srv.")) die_nomem();
        if (!stralloc_cat(&f[7], &f[0])) die_nomem();
      }
      domain_parse(&d1, &f[7]);
      rr_add_name(&d1);
      rr_finish(&fqdn);
      for (i = 8; i < fields.len; i++) {
	switch (ip_parse(&f[i], &ip4, &ip6)) {
	  case 4:
	    rr_start(dns_t_a, ttl, ttd, loc);
	    rr_add_ip4(&ip4);
	    rr_finish(&d1);
	    break;
	  case 6:
	    rr_start(dns_t_aaaa, ttl, ttd, loc);
	    rr_add_ip6(&ip6);
	    rr_finish(&d1);
	    break;
	  default:
	    die_field_missing("IP address");
	    break;
	}
      }
      continue;
    }

    if (stralloc_equals(&verb, "NAPTR")) {  /* DNS_T_NAPTR */
      pad_fields(10, &fields);
      rr_start(dns_t_naptr, ttl, ttd, loc);
      domain_parse(&d1, &f[4]);
      rr_add_uint16(uint_parse(&f[5], 0, "order"));
      rr_add_uint16(uint_parse(&f[6], 0, "pref"));
      txt_parse(&f[7]);
      if (f[7].len > 255) die_syntax_error(LONG_LABEL_MSG, &f[7]);
      rr_add_string(&f[7]);
      txt_parse(&f[8]);
      if (f[8].len > 255) die_syntax_error(LONG_LABEL_MSG, &f[8]);
      rr_add_string(&f[8]);
      txt_parse(&f[9]);
      if (f[9].len > 255) die_syntax_error(LONG_LABEL_MSG, &f[9]);
      rr_add_string(&f[9]);
      rr_add_name(&d1);
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "CAA")) {  /* DNS_T_CAA */
      pad_fields(7, &fields);
      rr_start(dns_t_caa, ttl, ttd, loc);
      rr_add_uint8(uint_parse(&f[4], 0, "flags"));
      txt_parse(&f[5]);  /* tag */
      stralloc_lower(&f[5]);
      if (stralloc_diffs(&f[5], "issue") && stralloc_diffs(&f[5], "issuewild") && stralloc_diffs(&f[5], "iodef")) {
        die_syntax_error("invalid tag", &f[5]);
      }
      rr_add_string(&f[5]);  /* tag */
      txt_parse(&f[6]);  /* value */
      rr_add(f[6].s, f[6].len);  /* value */
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "DNSKEY")) {  /* DNS_T_DNSKEY */
      pad_fields(7, &fields);
      rr_start(dns_t_dnskey, ttl, ttd, loc);
      u = uint_parse(&f[4], 0, "flags");
      if (u & 0xfe7e) {  /* 0xffff - 0x0001 - 0x0100 - 0x0080 */
        die_syntax_error("invalid flag", &f[4]);
      }
      rr_add_uint16(u);
      u = uint_parse(&f[5], 3, "protocol");
      if (u != 3) {
        die_syntax_error("invalid protocol", &f[5]);
      }
      rr_add_uint8(u);  /* protcol */
      rr_add_uint8(security_algorithm_parse(&f[6]));
      base64_parse(&f[7], &tmp);  /* public key */
      rr_add(tmp.s, tmp.len);
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "RRSIG")) {  /* DNS_T_RRSIG */
      pad_fields(13, &fields);
      rr_start(dns_t_rrsig, ttl, ttd, loc);
      rr_add_uint16(type_parse(&f[4]));
      rr_add_uint8(security_algorithm_parse(&f[5]));
      rr_add_uint16(uint_parse(&f[6], 0, "label count"));
      rr_add_uint32(ttl_parse(&f[7], TTL_POSITIVE));  /* original TTL */
      rr_add_uint32(uint_parse(&f[8], 0, "expiration timestamp"));
      rr_add_uint32(uint_parse(&f[9], 0, "inception timestamp"));
      rr_add_uint16(uint_parse(&f[10], 0, "key tag"));
      if (!f[11].len) die_field_missing("signer name");
      domain_parse(&d1, &f[11]);  /* name of signer */
      rr_add_name(&d1);
      base64_parse(&f[12], &tmp);  /* signature */
      rr_add(tmp.s, tmp.len);
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "NSEC")) {  /* DNS_T_NSEC */
      pad_fields(6, &fields);
      rr_start(dns_t_nsec, ttl, ttd, loc);
      if (!f[4].len) die_field_missing("next authoritative name");
      domain_parse(&d1, &f[4]);  /* next authoritative name */
      rr_add_name(&d1);
      if (!f[5].len) die_field_missing("RR type");
      if (!uint_vector_erase(&type_list)) die_nomem();
      for (i = 5; i < fields.len; ++i) {
	if (!uint_vector_append(&type_list, type_parse(&f[i]))) die_nomem();
      }
      rr_add_nsec_type_bits_map();
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "DS")) {  /* DNS_T_DS */
      pad_fields(8, &fields);
      rr_start(dns_t_rrsig, ttl, ttd, loc);
      rr_add_uint16(uint_parse(&f[4], 0, "key tag"));
      rr_add_uint8(security_algorithm_parse(&f[5]));
      rr_add_uint8(dnssec_digest_type_parse(&f[6]));
      hex_parse(&f[7], &tmp);  /* digest */
      rr_add(tmp.s, tmp.len);
      rr_finish(&fqdn);
      continue;
    }

    if (stralloc_equals(&verb, "?")) {  /* generic */
      pad_fields(6, &fields);
      if (!f[4].len) die_field_missing("RR type");
      if (!f[5].len) die_field_missing("RR data");
      u = type_parse(&f[4]);
      switch (u) {
        case DNS_T_AXFR:
        case DNS_T_IXFR:
        case DNS_T_NIL:
        case DNS_T_SOA:
        case DNS_T_NS:
        case DNS_T_CNAME:
        case DNS_T_PTR:
        case DNS_T_MX:
	case DNS_T_TXT:
	case DNS_T_NAPTR:
	case DNS_T_SRV:
	case DNS_T_CAA:
	case DNS_T_DNSKEY:
	case DNS_T_RRSIG:
	case DNS_T_NSEC:
	case DNS_T_DS:
	  die_type_prohibited(&f[4]);
	  break;
        default:
	  txt_parse(&f[5]);
	  dns_type_set(&type, u);
	  rr_start(&type, ttl, ttd, loc);
	  rr_add(f[5].s, f[5].len);
	  rr_finish(&fqdn);
	  break;
      }
      continue;
    }

    die_syntax_error("unrecognized verb", &verb);
  }

  if (cdb_make_finish(&cdb) < 0) die_datatmp();
  if (fsync(fd_cdb) < 0) die_datatmp();
  if (close(fd_cdb) < 0) die_datatmp();  /* NFS stupidity */
  if (rename("data.cdb.tmp", "data.cdb") < 0) die_move("data.cdb.tmp", "data.cdb");

  _exit(0);
}
