#include <nemo/alloc.h>
#include <nemo/fmt.h>
#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/exit.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/error.h>
#include <nemo/uint16.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "address4_vector.h"
#include "address6_vector.h"
#include "ns_vector.h"
#include "query_vector.h"
#include "qt_vector.h"
#include "dd.h"
#include "printrecord.h"
#include "die.h"
#include "safe.h"

const char USAGE[] = "type name rootip ...";

static stralloc querystr = STRALLOC;
static char ipstr[IP6_FMT];
static stralloc tmp = STRALLOC;

static void print_domain(const dns_domain *d)
{
  if (!stralloc_erase(&tmp)) die_nomem();
  if (!dns_domain_todot_cat(d, &tmp)) die_nomem();
  djbio_putsa(djbiofd_out, &tmp);
}

static struct dns6_transmit tx6 = DNS6_TRANSMIT;

static int resolve6(const dns_domain *q, dns_type *qtype, ip6_address *ip)
{
  static ip6_vector servers = IP6_VECTOR;

  struct taia start;
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  taia_now(&start);

  if (!ip6_vector_erase(&servers)) die_nomem();
  if (!ip6_vector_append(&servers, ip)) die_nomem();
  if (dns6_transmit_start(&tx6, &servers, 0, q, qtype, null_ip6) < 0) return -1;
  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);
    dns6_transmit_io(&tx6, x, &deadline);
    iopause(x, 1, &deadline, &stamp);
    r = dns6_transmit_get(&tx6, x, &stamp);
    if (r < 0) return -1;
    if (r) break;
  }
  taia_now(&stamp);
  taia_sub(&stamp, &stamp, &start);
  taia_uint(&deadline, 1);
  if (taia_less(&deadline, &stamp)) {
    djbio_putsa(djbiofd_out, &querystr);
    djbio_puts(djbiofd_out, "ALERT:took more than 1 second\n");
  }
  return 0;
}

static address4_vector address4 = ADDRESS4_VECTOR;
static address6_vector address6 = ADDRESS6_VECTOR;
static ns_vector ns = NS_VECTOR;
static query_vector query = QUERY_VECTOR;
static qt4_vector qt4 = QT4_VECTOR;
static qt6_vector qt6 = QT6_VECTOR;

static void qt4_add(const dns_domain *q, const dns_type *type, const dns_domain *control, const ip4_address *ip)
{
  static qt4_data x = QT4_DATA;
  unsigned int i;

  if (!dns_domain_labellength(q)) return;  /* don't ask the roots about our artificial . host */

  for (i = 0; i < qt4.len; ++i) {
    if (dns_domain_equal(&qt4.va[i].owner, q)) {
      if (dns_domain_equal(&qt4.va[i].control, control)) {
        if (dns_type_equal(&qt4.va[i].type, type)) {
          if (ip4_equal(&qt4.va[i].ip, ip)) {
            return;
          }
        }
      }
    }
  }

  if (!qt4_erase(&x)) die_nomem();
  if (!dns_domain_copy(&x.owner, q)) die_nomem();
  if (!dns_domain_copy(&x.control, control)) die_nomem();
  dns_type_copy(&x.type, type);
  ip4_copy(&x.ip, ip);
  if (!qt4_vector_append(&qt4, &x)) die_nomem();
}

static void qt6_add(const dns_domain *q, const dns_type *type, const dns_domain *control, const ip6_address *ip)
{
  static qt6_data x = QT6_DATA;
  unsigned int i;

  if (!dns_domain_labellength(q)) return;  /* don't ask the roots about our artificial . host */

  for (i = 0; i < qt6.len; ++i) {
    if (dns_domain_equal(&qt6.va[i].owner, q)) {
      if (dns_domain_equal(&qt6.va[i].control, control)) {
        if (dns_type_equal(&qt6.va[i].type, type)) {
          if (ip6_equal(&qt6.va[i].ip, ip)) {
            return;
          }
        }
      }
    }
  }

  if (!qt6_erase(&x)) die_nomem();
  if (!dns_domain_copy(&x.owner, q)) die_nomem();
  if (!dns_domain_copy(&x.control, control)) die_nomem();
  dns_type_copy(&x.type, type);
  ip6_copy(&x.ip, ip);
  if (!qt6_vector_append(&qt6, &x)) die_nomem();
}

static void query6_add(const dns_domain *owner, const dns_type *type)
{
  static query_data x = QUERY_DATA;
  unsigned int i;
  unsigned int j;

  for (i = 0; i < query.len; ++i) {
    if (dns_domain_equal(&query.va[i].owner, owner)) {
      if (dns_type_equal(&query.va[i].type, type)) return;
    }
  }

  if (!query_data_erase(&x)) die_nomem();
  if (!dns_domain_copy(&x.owner, owner)) die_nomem();
  dns_type_copy(&x.type, type);
  if (!query_vector_append(&query, &x)) die_nomem();

  for (i = 0; i < ns.len; ++i) {
    if (dns_domain_suffix(owner, &ns.va[i].owner)) {
      for (j = 0; j < address6.len; ++j) {
        if (dns_domain_equal(&ns.va[i].ns, &address6.va[j].name)) {
          qt6_add(owner, type, &ns.va[i].owner, &address6.va[j].ip);
        }
      }
    }
  }
}

static void ns6_add(const dns_domain *owner, const dns_domain *server)
{
  static ns_data x = NS_DATA;
  unsigned int i;
  unsigned int j;

  djbio_putsa(djbiofd_out, &querystr);
  djbio_put(djbiofd_out, "NS:", 3);
  print_domain(owner);
  djbio_put(djbiofd_out, ":", 1);
  print_domain(server);
  djbio_puteol(djbiofd_out);

  for (i = 0; i < ns.len; ++i) {
    if (dns_domain_equal(&ns.va[i].owner, owner)) {
      if (dns_domain_equal(&ns.va[i].ns, server)) return;
    }
  }

  query6_add(server, dns_t_aaaa);

  if (!ns_data_erase(&x)) die_nomem();
  if (!dns_domain_copy(&x.owner, owner)) die_nomem();
  if (!dns_domain_copy(&x.ns, server)) die_nomem();
  if (!ns_vector_append(&ns, &x)) die_nomem();

  for (i = 0; i < query.len; ++i) {
    if (dns_domain_suffix(&query.va[i].owner, owner)) {
      for (j = 0; j < address6.len; ++j) {
        if (dns_domain_equal(server, &address6.va[j].name)) {
          qt6_add(&query.va[i].owner, &query.va[i].type, owner, &address6.va[j].ip);
        }
      }
    }
  }
}

static void address4_add(const dns_domain *owner, const ip4_address *ip)
{
  static address4_data x = ADDRESS4_DATA;
  unsigned int i;
  unsigned int j;

  djbio_putsa(djbiofd_out, &querystr);
  djbio_put(djbiofd_out, "A:", 2);
  print_domain(owner);
  djbio_put(djbiofd_out, ":" , 1);
  djbio_put(djbiofd_out, ipstr, ip4_fmt(ip, ipstr));
  djbio_puteol(djbiofd_out);

  for (i = 0; i < address4.len; ++i) {
    if (dns_domain_equal(&address4.va[i].name, owner)) {
      if (ip4_equal(&address4.va[i].ip, ip)) return;
    }
  }

  if (!address4_data_erase(&x)) die_nomem();
  if (!dns_domain_copy(&x.name, owner)) die_nomem();
  ip4_copy(&x.ip, ip);
  if (!address4_vector_append(&address4, &x)) die_nomem();

  for (i = 0; i < ns.len; ++i) {
    if (dns_domain_equal(&ns.va[i].ns, owner)) {
      for (j = 0; j < query.len; ++j) {
        if (dns_domain_suffix(&query.va[j].owner, &ns.va[i].owner)) {
          qt4_add(&query.va[j].owner, &query.va[j].type, &ns.va[i].owner, ip);
        }
      }
    }
  }
}

static void address6_add(const dns_domain *owner, const ip6_address *ip)
{
  static address6_data x = ADDRESS6_DATA;
  unsigned int i;
  unsigned int j;

  djbio_putsa(djbiofd_out, &querystr);
  djbio_put(djbiofd_out, "AAAA:", 5);
  print_domain(owner);
  djbio_put(djbiofd_out, ":", 1);
  djbio_put(djbiofd_out, ipstr, ip6_fmt(ip, ipstr));
  djbio_puteol(djbiofd_out);

  for (i = 0; i < address6.len; ++i) {
    if (dns_domain_equal(&address6.va[i].name, owner)) {
      if (ip6_equal(&address6.va[i].ip, ip)) return;
    }
  }

  if (!address6_data_erase(&x)) die_nomem();
  if (!dns_domain_copy(&x.name, owner)) die_nomem();
  ip6_copy(&x.ip, ip);
  if (!address6_vector_append(&address6, &x)) die_nomem();

  for (i = 0; i < ns.len; ++i) {
    if (dns_domain_equal(&ns.va[i].ns, owner)) {
      for (j = 0; j < query.len; ++j) {
        if (dns_domain_suffix(&query.va[j].owner, &ns.va[i].owner)) {
          qt6_add(&query.va[j].owner, &query.va[j].type, &ns.va[i].owner, ip);
        }
      }
    }
  }
}

static dns_domain t1 = DNS_DOMAIN;
static dns_domain t2 = DNS_DOMAIN;
static dns_domain referral = DNS_DOMAIN;
static dns_domain cname = DNS_DOMAIN;

static int type_match(const dns_type *rtype, const dns_type *qtype)
{
  return dns_type_equal(qtype, rtype) || dns_type_equal(qtype, dns_t_any);
}

static void parse_packet6(const byte_t *buf, unsigned int len, const dns_domain *d, const dns_type *dtype, const dns_domain *control)
{
  ip4_address misc4;
  ip6_address misc6;
  dns_type type;
  dns_class class;
  byte_t header[12];
  byte_t tmpbuf[16];
  unsigned int pos;
  unsigned int pos_answers;
  unsigned int num_total;
  uint16_t num_answers;
  uint16_t num_authority;
  uint16_t num_glue;
  uint16_t data_len;
  unsigned int rcode;
  unsigned int flag_out;
  unsigned int flag_cname;
  unsigned int flag_referral;
  unsigned int flag_soa;
  unsigned int j;
  const char *x;

  pos = dns_packet_copy(buf, len, 0, header, 12);
  if (!pos) goto DIE;
  pos = dns_packet_skipname(buf, len, pos);
  if (!pos) goto DIE;
  pos += 4;

  uint16_unpack_big(&num_answers, header + 6);
  uint16_unpack_big(&num_authority, header + 8);
  uint16_unpack_big(&num_glue, header + 10);
  num_total = (unsigned int)num_answers + (unsigned int)num_authority + (unsigned int)num_glue;

  rcode = header[3] & 15;
  if (rcode && (rcode != 3)) {
    errno = error_proto;
    goto DIE;
  } /* impossible */

  flag_out = flag_cname = flag_referral = flag_soa = 0;
  pos_answers = pos;
  for (j = 0; j < num_answers; ++j) {
    pos = safe_packet_getname(buf, len, pos, &t1);
    if (!pos) goto DIE;
    pos = dns_packet_copy(buf, len, pos, header, 10);
    if (!pos) goto DIE;
    dns_type_unpack(&type, header);
    dns_class_unpack(&class, header + 2);
    if (dns_domain_equal(&t1, d)) {
      if (dns_class_equal(&class, dns_c_in)) {
        if (type_match(&type, dtype)) {
          flag_out = 1;
        }
        else if (type_match(&type, dns_t_cname)) {
          if (!safe_packet_getname(buf, len, pos, &cname)) goto DIE;
          flag_cname = 1;
        }
      }
    }
    uint16_unpack_big(&data_len, header + 8);
    pos += data_len;
  }
  for (j = 0; j < num_authority; ++j) {
    pos = safe_packet_getname(buf, len, pos, &t1);
    if (!pos) goto DIE;
    pos = dns_packet_copy(buf, len, pos, header, 10);
    if (!pos) goto DIE;
    dns_type_unpack(&type, header);
    dns_class_unpack(&class, header + 2);
    if (type_match(&type, dns_t_soa)) {
      flag_soa = 1;
    }
    else if (type_match(&type, dns_t_ns)) {
      flag_referral = 1;
      if (!dns_domain_copy(&referral, &t1)) die_nomem();
    }
    uint16_unpack_big(&data_len, header + 8);
    pos += data_len;
  }

  if (!flag_cname && !rcode && !flag_out && flag_referral && !flag_soa) {
    if (dns_domain_equal(&referral, control) || !dns_domain_suffix(&referral, control)) {
      djbio_putsa(djbiofd_out, &querystr);
      djbio_puts(djbiofd_out, "ALERT:lame server; refers to ");
      print_domain(&referral);
      djbio_puteol(djbiofd_out);
      return;
    }
  }

  pos = pos_answers;
  for (j = 0; j < num_total; ++j) {
    pos = safe_packet_getname(buf, len, pos, &t1);
    if (!pos) goto DIE;
    pos = dns_packet_copy(buf, len, pos, header, 10);
    if (!pos) goto DIE;
    dns_type_unpack(&type, header);
    dns_class_unpack(&class, header + 2);
    uint16_unpack_big(&data_len, header + 8);
    if (dns_domain_suffix(&t1, control)) {
      if (dns_class_equal(&class, dns_c_in)) {
        if (type_match(&type, dns_t_ns)) {
          if (!safe_packet_getname(buf, len, pos, &t2)) goto DIE;
          ns6_add(&t1, &t2);
        }
        else if (type_match(&type, dns_t_a) && data_len == 4) {
          if (!dns_packet_copy(buf, len, pos, tmpbuf, 4)) goto DIE;
          ip4_unpack(&misc4, tmpbuf);
          address4_add(&t1, &misc4);
        }
        else if (type_match(&type, dns_t_aaaa) && data_len == 16) {
          if (!dns_packet_copy(buf, len, pos, tmpbuf, 16)) goto DIE;
          ip6_unpack(&misc6, tmpbuf);
          address6_add(&t1, &misc6);
        }
      }
    }
    pos += data_len;
  }


  if (flag_cname) {
    query6_add(&cname, dtype);
    djbio_putsa(djbiofd_out, &querystr);
    djbio_puts(djbiofd_out, "CNAME:");
    print_domain(&cname);
    djbio_puteol(djbiofd_out);
    return;
  }
  if (rcode == 3) {
    djbio_putsa(djbiofd_out, &querystr);
    djbio_puts(djbiofd_out, "NXDOMAIN\n");
    return;
  }
  if (flag_out || flag_soa || !flag_referral) {
    if (!flag_out) {
      djbio_putsa(djbiofd_out, &querystr);
      djbio_puts(djbiofd_out, "NODATA\n");
      return;
    }
    pos = pos_answers;
    for (j = 0; j < num_total; ++j) {
      pos = printrecord(buf, len, pos, d, dtype, &tmp);
      if (!pos) goto DIE;
      if (tmp.len) {
        djbio_putsa(djbiofd_out, &querystr);
        djbio_puts(djbiofd_out, "answer:");
        djbio_putsa(djbiofd_out, &tmp); /* includes \n */
      }
    }
    return;
  }

  if (!dns_domain_suffix(d, &referral)) goto DIE;
  djbio_putsa(djbiofd_out, &querystr);
  djbio_puts(djbiofd_out, "see:");
  print_domain(&referral);
  djbio_puteol(djbiofd_out);
  return;

DIE:
  x = error_str(errno);
  djbio_putsa(djbiofd_out, &querystr);
  djbio_puts(djbiofd_out, "ALERT:unable to parse response packet; ");
  djbio_puts(djbiofd_out, x);
  djbio_puteol(djbiofd_out);
}

int main(int argc __UNUSED__, char **argv)
{
  static ip6_vector out6 = IP4_VECTOR;
  static stralloc fqdn = STRALLOC;
  static stralloc udn = STRALLOC;
  static dns_domain qname = DNS_DOMAIN;
  static dns_domain control = DNS_DOMAIN;
  char seed[128];
  dns_type type;
  ip6_address ip6;
  unsigned int i;

  PROGRAM = *argv;
  dns_random_init(seed);

  if (!stralloc_copys(&querystr, "0:.:.:start:")) die_nomem();

  if (!address4_vector_readyplus(&address4, 1)) die_nomem();
  if (!address6_vector_readyplus(&address6, 1)) die_nomem();
  if (!query_vector_readyplus(&query, 1)) die_nomem();
  if (!ns_vector_readyplus(&ns, 1)) die_nomem();
  if (!qt4_vector_readyplus(&qt4, 1)) die_nomem();
  if (!qt6_vector_readyplus(&qt6, 1)) die_nomem();

  if (!*++argv) die_usage1("missing type");
  if (!dns_type_parse(&type, *argv)) die_usage();

  if (!*++argv) die_usage1("missing name");
  if (!dns_domain_fromdot(&qname, *argv, str_len(*argv))) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_parse("name", *argv);
    die_internal();
  }

  query6_add(&qname, &type);
  ns6_add(dns_d_empty, dns_d_empty);
  while (*++argv) {
    if (!stralloc_copys(&udn, *argv)) die_nomem();
    if (dns6_ip6_qualify(&out6, &fqdn, &udn) < 0) {
      if (errno == error_nomem) die_nomem();
      if (errno == error_proto) die_parse("bad root ip", *argv);
      die_internal();
    }
    for (i = 0; i < out6.len; i++) {
      address6_add(dns_d_empty, &out6.va[i]);
    }
  }
  for (i = 0; i < qt6.len; ++i) {
    if (!dns_domain_copy(&qname, &qt6.va[i].owner)) die_nomem();
    if (!dns_domain_copy(&control, &qt6.va[i].control)) die_nomem();
    if (!dns_domain_suffix(&qname, &control)) continue;
    dns_type_copy(&type, &qt6.va[i].type);
    ip6_copy(&ip6, &qt6.va[i].ip);

    if (!stralloc_erase(&querystr)) die_nomem();
    if (!stralloc_catulong0(&querystr, dns_type_get(&type), 0)) die_nomem();
    if (!stralloc_append(&querystr, ":")) die_nomem();
    if (!dns_domain_todot_cat(&qname, &querystr)) die_nomem();
    if (!stralloc_append(&querystr, ":")) die_nomem();
    if (!dns_domain_todot_cat(&control, &querystr)) die_nomem();
    if (!stralloc_append(&querystr, ":")) die_nomem();
    if (!stralloc_catb(&querystr, ipstr, ip6_fmt(&ip6, ipstr))) die_nomem();
    if (!stralloc_append(&querystr, ":")) die_nomem();

    djbio_putsa(djbiofd_out, &querystr);
    djbio_put(djbiofd_out, "tx\n", 3);
    djbio_flush(djbiofd_out);

    if (resolve6(&qname, &type, &ip6) < 0) {
      const char *x = error_str(errno);
      djbio_putsa(djbiofd_out, &querystr);
      djbio_puts(djbiofd_out, "ALERT:query failed; ");
      djbio_puts(djbiofd_out, x);
      djbio_puteol(djbiofd_out);
    }
    else {
      parse_packet6(tx6.packet, tx6.packetlen, &qname, &type, &control);
    }

    if (dns_domain_equal(&qname, dns_d_ip6_localhost)) {
      djbio_putsa(djbiofd_out, &querystr);
      djbio_puts(djbiofd_out, "ALERT:some caches do not handle localhost internally\n");
      address6_add(&qname, localhost_ip6);
    }
/*
    if (dd6(&qname, dns_d_empty, &ip6) == 32) {
      djbio_putsa(djbiofd_out, &querystr);
      djbio_puts(djbiofd_out, "ALERT:some caches do not handle IPv6 addresses internally\n");
      address6_add(&qname, &ip6);
    }
*/
    djbio_flush(djbiofd_out);
  }

  _exit(0);
}
