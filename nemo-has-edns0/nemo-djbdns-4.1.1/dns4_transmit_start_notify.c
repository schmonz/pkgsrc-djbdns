#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/alloc.h>
#include <nemo/error.h>
#include <nemo/byte.h>
#include <nemo/unix.h>
#include <nemo/uint16.h>

#include "dns.h"
#include "dns4_transmit.h"

#define	QUERY_OVERHEAD_SIZE	(unsigned int)sizeof(uint16_t) + (unsigned int)sizeof(uint16_t)

#define	MIN_DATA_SIZE		DNS_HEADER_SIZE + QUERY_OVERHEAD_SIZE

#define	MIN_PACKET_SIZE		(unsigned int)sizeof(uint16_t) + MIN_DATA_SIZE

int dns4_transmit_start_notify(struct dns4_transmit *dt, ip4_vector *servers, const dns_domain *qname, const ip4_address *localip)
{
  register byte_t *buf;
  register unsigned int qname_len;

  dns4_transmit_free(dt);
  errno = error_io;

  qname_len = dns_domain_length(qname);
  dt->querylen = qname_len + MIN_PACKET_SIZE;
  buf = dt->query = alloc(dt->querylen);
  if (!buf) return -1;
/*
  packet payload size
*/
  uint16_pack_big((uint16_t)(qname_len + MIN_DATA_SIZE), buf);
  buf += sizeof(uint16_t);
/*
  packet header
*/
  byte_copy(buf, DNS_HEADER_SIZE, "\000\000\044\000\000\001\000\000\000\000\000\000gcc-bug-workaround");  /* NOTIFY + AA */
  buf += DNS_HEADER_SIZE;
/*
  query section
*/
  dns_domain_pack(qname, buf);
  buf += qname_len;
  dns_type_pack(dns_t_soa, buf);
  dns_class_pack(dns_c_in, buf + 2);
/*
  house keeping
*/
  dns_type_copy(&dt->qtype, dns_t_soa);
  dt->servers = servers;
  ip4_copy(&dt->localip, localip);
  dt->udploop = 0;
/*
  do it
*/
  if (dt->querylen > DNS_UDP_SIZE_DEFAULT) {
    return dns4_transmit_first_tcp(dt);
  }
  return dns4_transmit_first_udp(dt);
}
