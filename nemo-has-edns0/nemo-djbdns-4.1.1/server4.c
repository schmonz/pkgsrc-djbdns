#include <nemo/byte.h>
#include <nemo/env.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/ndelay.h>
#include <nemo/socket.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "droproot.h"
#include "qlog.h"
#include "response.h"
#include "respond.h"
#include "die.h"
#include "safe.h"

static byte_t buf[DNS_UDP_SIZE_MAX+1];
static unsigned int len;

static unsigned int server4_doit(ip4_address *ip, uint16_t port, unsigned int *udp_size)
{
  static dns_domain qname = DNS_DOMAIN;
  register byte_t *x;
  const char *result;
  byte_t header[12];
  byte_t misc[4];
  dns_type additional_section_type;
  dns_type qtype;
  dns_class qclass;
  dns_id qid;
  unsigned int type;
  unsigned int i;
  unsigned int r;
  unsigned int pos;
  unsigned int num_total;
  unsigned int flag_edns0;
  uint16_t num_answers;
  uint16_t num_authority;
  uint16_t num_additional;
  uint16_t rr_data_len;
  uint16_t udp_payload_size;

  flag_edns0 = 0;
  udp_payload_size = 0;
  if (len >= sizeof buf) goto NOQ;
  pos = dns_packet_copy(buf, len, 0, header, DNS_HEADER_SIZE);
  if (!pos) goto NOQ;
  dns_id_unpack(&qid, header);
/*
  query section
*/
  pos = safe_packet_getname(buf, len, pos, &qname);
  if (!pos) goto NOQ;
  pos = dns_packet_copy(buf, len, pos, misc, 4);
  if (!pos) goto NOQ;
  dns_type_unpack(&qtype, misc);
  dns_class_unpack(&qclass, misc + 2);
  type = dns_type_get(&qtype);

  if (!response_query(&qname, &qtype, &qclass)) goto NOQ;
  response_id(&qid);
  if (dns_class_equal(&qclass, dns_c_in)) {
    response[2] |= 4;
  }
  else {
    if (dns_class_diff(&qclass, dns_c_any)) goto FORMERR;
  }
  response[3] &= (byte_t)(~128);
  if (!(header[2] & 1)) {
    response[2] &= (byte_t)(~1);
  }
/*
  process header, part 2
*/
  if (header[2] & 128) goto FORMERR;     /* must not respond to responses */
  if (header[4]) goto FORMERR;           /* ignore more than 1 question, 1/2 */
  if (header[5] != 1) goto FORMERR;      /* ignore more than 1 question, 2/2 */

  if ((header[2] & 126) == 0x24) {  /* NOTIFY + AA */
    if (type == DNS_T_SOA) {
      response[2] |= 0x20;  /* NOTIFY */
      qlog4(ip, port, &qid, &qname, &qtype, " N ");
      return 1;
    }
  }

  if (header[2] & 126) goto FORMERR;    /* ignore non-zero opcodes, AA, TC */
  if (type == DNS_T_AXFR) goto NOTIMP;  /* ignore AXFR */
  if (type == DNS_T_IXFR) goto NOTIMP;  /* ignore IXFR */
  if (type == DNS_T_OPT) goto NOTIMP;  	/* ignore OPT in request, ok in additional section */

  uint16_unpack_big(&num_answers, header + DNS_HEADER_ANSWER_COUNT_OFFSET);
  uint16_unpack_big(&num_authority, header + DNS_HEADER_AUTHORITY_COUNT_OFFSET);
  uint16_unpack_big(&num_additional, header + DNS_HEADER_ADDITIONAL_COUNT_OFFSET);
/*
  answers + authority section
*/
  num_total = (unsigned int)num_answers + (unsigned int)num_authority;
  for (i = 0; i < num_total; i++) {
    pos = dns_packet_skipname(buf, len, pos);
    if (!pos) goto FORMERR;
    pos = dns_packet_copy(buf, len, pos, header, DNS_RR_HEADER_SIZE);  /* type, class, ttl, rr_data_len */
    if (!pos) goto FORMERR;
    uint16_unpack_big(&rr_data_len, header + 8);
    pos += rr_data_len;
    if (pos > len) goto FORMERR;  /* bad structure */
  }
/*
  additional section
*/
  num_total = num_additional;
  for (i = 0; i < num_total; i++) {
    pos = dns_packet_skipname(buf, len, pos);
    if (!pos) goto FORMERR;
    pos = dns_packet_copy(buf, len, pos, header, DNS_RR_HEADER_SIZE);  /* type, class, ttl, rr_data_len */
    if (!pos) goto FORMERR;
    dns_type_unpack(&additional_section_type, header);
    type = dns_type_get(&additional_section_type);
    if (type == DNS_T_OPT) {
      flag_edns0++;
      uint16_unpack_big(&udp_payload_size, header + DNS_RR_CLASS_OFFSET);  /* class contains UDP payload size */
      x = header + DNS_RR_TTL_OFFSET;  /* TTL contains extended rcode + version + flags */
      if (*x) goto FORMERR;  /* extended rcode */
      if (x[1]) goto BADVERS;  /* only support version == 0 */
    }
    uint16_unpack_big(&rr_data_len, header + DNS_RR_DATA_LENGTH_OFFSET);
    pos += rr_data_len;
    if (pos > len) goto FORMERR;  /* bad structure */
  }
  if (flag_edns0 > 1) goto FORMERR;
  if (udp_payload_size < DNS_UDP_SIZE_DEFAULT) {  /* rfc6891 */
    udp_payload_size = DNS_UDP_SIZE_DEFAULT;
  }
  else if (udp_payload_size > DNS_UDP_SIZE_MAX) {
    udp_payload_size = DNS_UDP_SIZE_MAX;
  }
  *udp_size = udp_payload_size;

  dns_domain_lower(&qname);
  r = respond4(&qname, &qtype, ip, *udp_size, flag_edns0);
  switch (r) {
    case 0:  /* error - response NOT possible */
      result = " E ";
      break;
    case 1:  /* ok (+ve result) */
      result = " + ";
      break;
    case 2:  /* no answer section (-ve result) */
      result = " - ";
      break;
    case 3:  /* rejected */
      result = " R ";
      break;
    default:  /* unknown - internal error */
      response_servfail();
      result = " ? ";
      break;
  }
  qlog4(ip, port, &qid, &qname, &qtype, result);
  return r;

NOTIMP:
  response_notimp();
  qlog4(ip, port, &qid, &qname, &qtype, " I ");
  return 1;

FORMERR:
  response_formerr();
  qlog4(ip, port, &qid, &qname, &qtype, " F ");
  return 1;
/*
REFUSE:
  response_refused();
  qlog4(ip, port, &qid, &qname, &qtype, " R ");
  return 1;
*/
BADVERS:
  response_opt_error(DNS_RCODE_BADVERS);
  qlog4(ip, port, &qid, &qname, &qtype, " V ");
  return 1;

NOQ:
  dns_id_unpack(&qid, "\0\0");
  qlog4(ip, port, &qid, dns_d_empty, dns_t_nil, " / ");
  return 0;
}

int main(int argc __UNUSED__, char **argv)
{
  ip4_address ip;
  unsigned int udp_size;
  unsigned int i;
  const char *x;
  int r;
  int udp53;
  uint16_t port;

  PROGRAM = *argv;
  x = env_get("IP");
  if (!x || !*x) die_env("IP");
  i = ip4_scan(&ip, x);
  if (!i || x[i]) die_parse("IP address", x);

  udp53 = socket4_udp();
  if (udp53 < 0) die_create("UDP socket");
  if (socket4_bind_reuse(udp53, &ip, 53) < 0) die_bind("UDP");

  droproot();

  initialize();

  ndelay_off(udp53);
  socket_try_reserve_in(udp53, 65536);

  qlog_starting(PROGRAM);

  udp_size = DNS_UDP_SIZE_DEFAULT;  /* compiler noise */
  for (;;) {
    r = socket4_recv(udp53, buf, sizeof(buf), &ip, &port);
    if (r < 0) continue;
    len = (unsigned int)r;
    if (!server4_doit(&ip, port, &udp_size)) continue;
    if (response_len > udp_size) response_tc();
    response_send4(udp53, &ip, port);
    /* may block for buffer space; if it fails, too bad */
  }
}
