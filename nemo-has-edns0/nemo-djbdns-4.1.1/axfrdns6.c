#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/exit.h>
#include <nemo/env.h>
#include <nemo/tai.h>
#include <nemo/cdb.h>
#include <nemo/stralloc.h>
#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/scan.h>
#include <nemo/djbio.h>
#include <nemo/timeoutio.h>
#include <nemo/unix.h>
#include <nemo/uint32.h>
#include <nemo/error.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "die.h"
#include "qlog.h"
#include "response.h"
#include "droproot.h"
#include "respond.h"
#include "safe.h"
#include "data_cdb.h"
#include "tdlookup.h"

static void die_truncated(void)
{
  die_bogus_query("truncated request");
}
static void die_outside(void)
{
  die1("unable to locate information in data.cdb");
}
static void die_cdbread(void)
{
  die_read("data.cdb");
}
static void die_cdbformat(void)
{
  die_read("data.cdb: format error");
}

static ssize_t safewrite(int fd, const void *buf, size_t len)
{
  ssize_t w;
  w = timeoutio_write(60, fd, buf, len);
  if (w <= 0) die_write("network");
  return w;
}

static byte_t net_writespace[1024];
static djbio net_write = DJBIO_INITWRITE(safewrite, 1, net_writespace, sizeof net_writespace);

static void print(void *buf, unsigned int len)
{
  byte_t tcp_header[2];
  uint16_pack_big((uint16_t)len, tcp_header);
  djbio_put(&net_write, tcp_header, 2);
  djbio_put(&net_write, buf, len);
  djbio_flush(&net_write);
}

static const char *axfr;
static dns_domain axfr_ok = DNS_DOMAIN;

static void axfr_check(const dns_domain *q)
{
  unsigned int i;
  unsigned int j;
  if (!axfr) return;
  i = j = 0;
  for (;;) {
    if (!axfr[i] || (axfr[i] == '/')) {
      if (i > j) {
        if (!dns_domain_fromdot(&axfr_ok, axfr + j, i - j)) {
	  if (errno == error_nomem) die_nomem();
	  if (errno == error_proto) die_bogus_query("bad zone name");
	  die_internal();
        }
        if (dns_domain_equal(q, &axfr_ok)) return;
      }
      j = i + 1;
    }
    if (!axfr[i]) break;
    ++i;
  }
  die_bogus_query("disallowed zone transfer request");
}

static dns_domain zone = DNS_DOMAIN;

static uint32_t pos_cdb;

static void get(byte_t *buf, unsigned int len)
{
  register int r;

  r = cdb_read(&data_cdb, buf, len, pos_cdb);
  if (r < 0) die_cdbread();
  pos_cdb += len;
}

static uint32_t getnum(void)
{
  byte_t buf[sizeof(uint32_t)];

  get(buf, sizeof(uint32_t));
  return cdb_unpack(buf);
}

static ip6_address ip;
static uint16_t port;

static struct tai now;
static byte_t data[32767];
static uint32_t dlen;
static uint32_t dpos;

static void copy(byte_t *buf, unsigned int len)
{
  dpos = dns_packet_copy(data, dlen, dpos, buf, len);
  if (!dpos) die_cdbread();
}

static void do_name(stralloc *sa)
{
  static dns_domain d = DNS_DOMAIN;
  dpos = safe_packet_getname(data, dlen, dpos, &d);
  if (!dpos) die_cdbread();
  if (!stralloc_catb(sa, d.data, d.len)) die_nomem();
}

static int build(stralloc *sa, const dns_domain *q, unsigned int flag_soa, const dns_id *id)
{
  unsigned int rdatapos;
  byte_t tmp[2];
  byte_t misc[20];
  byte_t recordloc[2];
  byte_t ttl[4];
  byte_t ttd[8];
  dns_type type;
  struct tai cutoff;

  dpos = 0;
  copy(misc, 2);
  dns_type_unpack(&type, misc);
  if (flag_soa) {
    if (dns_type_diff(&type, dns_t_soa)) return 0;
  }
  if (!flag_soa) {
    if (dns_type_equal(&type, dns_t_soa)) return 0;
  }

  dns_id_pack(id, tmp);
  if (!stralloc_copyb(sa, tmp, 2)) die_nomem();
  if (!stralloc_catb(sa, "\204\000\0\0\0\1\0\0\0\0", 10)) die_nomem();
  copy(misc, 1);
  if ((misc[0] == '=' + 1) || (misc[0] == '*' + 1)) {
    --misc[0];
    copy(recordloc, 2);
    if (byte_diff(recordloc, 2, client_loc)) return 0;
  }
  if (misc[0] == '*') {
    if (flag_soa) return 0;
    if (!stralloc_catb(sa, "\1*", 2)) die_nomem();
  }
  if (!stralloc_catb(sa, q->data, q->len)) die_nomem();
  dns_type_pack(&type, misc);
  if (!stralloc_catb(sa, misc, 2)) die_nomem();

  copy(ttl, 4);
  copy(ttd, 8);
  if (byte_diff(ttd, 8, "\0\0\0\0\0\0\0\0")) {
    tai_unpack(&cutoff, ttd);
    if (byte_equal(ttl, 4, "\0\0\0\0")) {
      if (tai_less(&cutoff, &now)) return 0;
      uint32_pack_big(2, ttl);
    }
    else {
      if (!tai_less(&cutoff, &now)) return 0;
    }
  }

  dns_class_pack(dns_c_in, misc);
  if (!stralloc_catb(sa, misc, 2)) die_nomem();
  if (!stralloc_catb(sa, ttl, 4)) die_nomem();
  if (!stralloc_catb(sa, "\0\0", 2)) die_nomem();
  rdatapos = sa->len;

  if (dns_type_equal(&type, dns_t_soa)) {
    do_name(sa);
    do_name(sa);
    copy(misc, 20);
    if (!stralloc_catb(sa, misc, 20)) die_nomem();
  }
  else if (dns_type_equal(&type, dns_t_ns) || dns_type_equal(&type, dns_t_ptr) || dns_type_equal(&type, dns_t_cname)) {
    do_name(sa);
  }
  else if (dns_type_equal(&type, dns_t_mx)) {
    copy(misc, 2);
    if (!stralloc_catb(sa, misc, 2)) die_nomem();
    do_name(sa);
  }
  else {
    if (!stralloc_catb(sa, data + dpos, dlen - dpos)) die_nomem();
  }

  if (sa->len > 65535) die_cdbformat();
  uint16_pack_big((uint16_t)(sa->len - rdatapos), sa->s + rdatapos - 2);
  return 1;
}

static dns_domain q = DNS_DOMAIN;
static stralloc soa = STRALLOC;
static stralloc message = STRALLOC;

static void do_axfr(const dns_id *id)
{
  byte_t key[512];
  uint32_t klen;
  uint32_t eod;
  unsigned int nlen;
  int r;

  axfr_check(&zone);

  tai_now(&now);

  data_cdb_setup();
  key[0] = '\0';
  key[1] = '%';
  key[2] = '4';
  key[3] = '\0';  /* padding */
  ip6_pack(&ip, key + KEY_PREFIX_LEN);
  if (!tdlookup_loc_setup(key, KEY_PREFIX_LEN+16)) die_cdbformat();

  cdb_findstart(&data_cdb);
  for (;;) {
    r = cdb_findnext(&data_cdb, zone.data, zone.len);
    if (r < 0) die_cdbread();
    if (!r) die_outside();
    dlen = cdb_datalen(&data_cdb);
    if (dlen > sizeof data) die_cdbformat();
    if (cdb_read(&data_cdb, data, dlen, cdb_datapos(&data_cdb)) < 0) die_cdbformat();
    if (build(&soa, &zone, 1, id)) break;
  }

  print(soa.s, soa.len);

  pos_cdb = 0;
  eod = getnum();
  /* skip cdb header */
  pos_cdb = 2048;
  while (pos_cdb < eod) {
    klen = getnum();
    dlen = getnum();
    if (klen > sizeof key) die_cdbformat();
    get(key, klen);
    if (dlen > sizeof data) die_cdbformat();
    get(data, dlen);
    if ((klen > 1) && (key[0] == 0)) continue; /* location */
    if (klen < 1) die_cdbformat();
    nlen = safe_packet_getname(key, klen, 0, &q);
    if (nlen != klen) die_cdbformat();
    if (!dns_domain_suffix(&q, &zone)) continue;
    if (!build(&message, &q, 0, id)) continue;
    print(message.s, message.len);
  }

  print(soa.s, soa.len);
}

static void net_read(byte_t *buf, unsigned int len)
{
  ssize_t r;
  while (len > 0) {
    r = timeoutio_read(60, 0, buf, len);
    if (r == 0) _exit(0);
    if (r < 0) die_read("network");
    buf += r;
    len -= (unsigned int)r;
  }
}

static byte_t tcp_header[2];
static byte_t buf[DNS_UDP_SIZE_DEFAULT];
static uint16_t len;

int main(int argc __UNUSED__, char **argv)
{
  char seed[128];
  unsigned int pos;
  byte_t header[12];
  byte_t tmp[2];
  dns_type qtype;
  dns_class qclass;
  dns_id qid;
  const char *x;
  unsigned long u;

  PROGRAM = *argv;
  droproot();
  dns_random_init(seed);

  axfr = env_get("AXFR");

  x = env_get("TCPREMOTEIP");
  if (x && *x) {
    pos = ip6_scan(&ip, x);
    if (x[pos]) die_parse("$TCPREMOTEIP", x);
  }
  else {
    ip6_zero(&ip);
  }

  x = env_get("TCPREMOTEPORT");
  if (!x) {
    x = "0";
  }
  pos = scan_ulong(x, &u);
  if (x[pos]) die_parse("$TCPREMOTEPORT", x);
  port = (uint16_t)u;

  for (;;) {
    net_read(tcp_header, 2);
    uint16_unpack_big(&len, tcp_header);
    if (len > DNS_UDP_SIZE_DEFAULT) die_bogus_query("excessively large request");
    net_read(buf, len);

    pos = dns_packet_copy(buf, len, 0, header, 12);
    if (!pos) die_truncated();
    if (header[2] & 254) die_bogus_query("bad OPCODE, et al");
    if (header[4] || (header[5] != 1)) die_bogus_query("bad QDCOUNT");
    dns_id_unpack(&qid, header);

    pos = safe_packet_getname(buf, len, pos, &zone);
    if (!pos) die_truncated();
    pos = dns_packet_copy(buf, len, pos, tmp, 2);
    if (!pos) die_truncated();
    dns_type_unpack(&qtype, tmp);
    pos = dns_packet_copy(buf, len, pos, tmp, 2);
    if (!pos) die_truncated();
    dns_class_unpack(&qclass, tmp);

    if (dns_class_diff(&qclass, dns_c_in) && dns_class_diff(&qclass, dns_c_any)) {
      die_bogus_query("bad class");
    }

    qlog6(&ip, port, &qid, &zone, &qtype, " ");

    if (dns_type_equal(&qtype, dns_t_axfr) || dns_type_equal(&qtype, dns_t_ixfr)) {
      dns_domain_lower(&zone);
      do_axfr(&qid);
    }
    else {
      if (!response_query(&zone, &qtype, &qclass)) die_nomem();
      response[2] |= 4;
      dns_domain_lower(&zone);
      response_id(&qid);
      response[3] &= (byte_t)(~128);
      if (!(header[2] & 1)) {
        response[2] &= (byte_t)(~1);
      }
      if (!respond6(&zone, &qtype, &ip, DNS_UDP_SIZE_DEFAULT, 0)) die_outside();
      print(response, response_len);
    }
  }
  return 0;  /* lint */
}
