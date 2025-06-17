#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/alloc.h>
#include <nemo/error.h>
#include <nemo/byte.h>
#include <nemo/unix.h>
#include <nemo/socket.h>
#include <nemo/uint16.h>

#include "dns.h"
#include "dns4_transmit.h"

static unsigned int server_wants_tcp(const byte_t *buf, unsigned int len)
{
  byte_t out[12];

  if (!dns_packet_copy(buf, len, 0, out, sizeof(out))) return 1;
  if (out[2] & 2) return 1;
  return 0;
}

static unsigned int server_failed(const byte_t *buf, unsigned int len)
{
  byte_t out[12];
  unsigned int rcode;

  if (!dns_packet_copy(buf, len, 0, out, sizeof(out))) return 1;
  rcode = out[3];
  rcode &= 15;
  if (rcode && (rcode != DNS_RCODE_NXDOMAIN)) {  /* !NOERROR && !NXDOMAIN*/
    errno = error_again;
    return 1;
  }
  return 0;
}

static int irrelevant(struct dns4_transmit *dt, const byte_t *buf, unsigned int len)
/*
  returns:
    -1 = fatal,
     0 = OK,
     1 = irrelevant
*/
{
  static dns_domain dn = DNS_DOMAIN;
  static dns_domain qd = DNS_DOMAIN;
  byte_t out[12];
  unsigned int pos;

  pos = dns_packet_copy(buf, len, 0, out, sizeof(out));
  if (!pos) return 1;
  if (byte_diff(out, 2, dt->query + 2)) return 1;
  if (out[4] != 0) return 1;
  if (out[5] != 1) return 1;

  pos = dns_packet_getname(buf, len, pos, &dn);
  if (!pos) {
    if (errno == error_nomem) return -1;  /* fatal */
    return 1;
  }
  if (!dns_domain_unpack(&qd, dt->query + 14)) return -1;  /* fatal */
  if (!dns_domain_equal(&dn, &qd)) return 1;

  pos = dns_packet_copy(buf, len, pos, out, 4);
  if (!pos) return 1;
  if (!dns_type_equalb(&dt->qtype, out)) return 1;
  if (!dns_class_equalb(dns_c_in, out + 2)) return 1;

  return 0;
}

static void dns4_transmit_packet_free(struct dns4_transmit *dt)
{
  if (!dt->packet) return;
  alloc_free(dt->packet);
  dt->packet = 0;
}

static void dns4_transmit_query_free(struct dns4_transmit *dt)
{
  if (!dt->query) return;
  alloc_free(dt->query);
  dt->query = 0;
}

static void dns_socket_free(struct dns4_transmit *dt)
{
  if (dt->s < 0) return;
  close(dt->s);
  dt->s = -1;
}

void dns4_transmit_free(struct dns4_transmit *dt)
{
  dt->servers = 0;
  dns4_transmit_query_free(dt);
  dns_socket_free(dt);
  dns4_transmit_packet_free(dt);
}

static int random_bind(struct dns4_transmit *dt)
{
  unsigned int j;

  for (j = 0; j < 10; ++j) {
    if (socket4_bind(dt->s, &dt->localip, (uint16_t)(1025 + dns_random(64510))) == 0) {
      return 0;
    }
  }
  if (socket4_bind(dt->s, &dt->localip, 0) == 0) return 0;
  return -1;
}

static const unsigned int timeouts[4] = { 1, 3, 11, 45 };

static int this_udp(struct dns4_transmit *dt)
{
  struct taia now;
  ip4_address *ip;

  dns_socket_free(dt);

  while (dt->udploop < 4) {
    for (; dt->curserver < dt->servers->len; ++dt->curserver) {
      ip = &dt->servers->va[dt->curserver];
      dt->query[2] = (byte_t)dns_random(256);
      dt->query[3] = (byte_t)dns_random(256);

      dt->s = socket4_udp();
      if (dt->s < 0) {
        dns4_transmit_free(dt);
        return -1;
      }
      if (random_bind(dt) < 0) {
        dns4_transmit_free(dt);
        return -1;
      }

      if (socket4_connect(dt->s, ip, 53) == 0) {
        if (send(dt->s, dt->query + 2, dt->querylen - 2, 0) == (int)(dt->querylen - 2)) {
          taia_now(&now);
          taia_uint(&dt->deadline, timeouts[dt->udploop]);
          taia_add(&dt->deadline, &dt->deadline, &now);
          dt->tcpstate = 0;
          return 0;
        }
      }

      dns_socket_free(dt);
    }

    ++dt->udploop;
    dt->curserver = 0;
  }

  dns4_transmit_free(dt);
  return -1;
}

int dns4_transmit_first_udp(struct dns4_transmit *dt)
{
  dt->curserver = 0;
  return this_udp(dt);
}

static int next_udp(struct dns4_transmit *dt)
{
  dt->curserver++;
  return this_udp(dt);
}

static int this_tcp(struct dns4_transmit *dt)
{
  struct taia now;
  ip4_address *ip;

  dns_socket_free(dt);
  dns4_transmit_packet_free(dt);

  for (; dt->curserver < dt->servers->len; ++dt->curserver) {
    ip = &dt->servers->va[dt->curserver];
    dt->query[2] = (byte_t)dns_random(256);
    dt->query[3] = (byte_t)dns_random(256);

    dt->s = socket4_tcp();
    if (dt->s < 0) {
      dns4_transmit_free(dt);
      return -1;
    }
    if (random_bind(dt) < 0) {
      dns4_transmit_free(dt);
      return -1;
    }

    taia_now(&now);
    taia_uint(&dt->deadline, 10);
    taia_add(&dt->deadline, &dt->deadline, &now);
    if (socket4_connect(dt->s, ip, 53) == 0) {
      dt->pos = 0;
      dt->tcpstate = 2;
      return 0;
    }
    if ((errno == error_inprogress) || (errno == error_wouldblock)) {
      dt->tcpstate = 1;
      return 0;
    }

    dns_socket_free(dt);
  }

  dns4_transmit_free(dt);
  return -1;
}

int dns4_transmit_first_tcp(struct dns4_transmit *dt)
{
  dt->curserver = 0;
  return this_tcp(dt);
}

static int next_tcp(struct dns4_transmit *dt)
{
  dt->curserver++;
  return this_tcp(dt);
}

void dns4_transmit_init(struct dns4_transmit *dt)
{
  dt->s = -1;
  dt->query = 0;
  dt->packet = 0;
}

void dns4_transmit_io(struct dns4_transmit *dt, iopause_fd *x, struct taia *deadline)
{
  x->fd = dt->s;

  switch (dt->tcpstate) {
    case 0:
    case 3:
    case 4:
    case 5:
      x->events = IOPAUSE_READ;
      break;
    case 1:
    case 2:
      x->events = IOPAUSE_WRITE;
      break;
    default:
      break;
  }

  if (taia_less(&dt->deadline, deadline)) {
    *deadline = dt->deadline;
  }
}

int dns4_transmit_get(struct dns4_transmit *dt, iopause_fd *x, const struct taia *when)
{
  struct taia now;
  byte_t udp_buf[DNS_UDP_SIZE_MAX+1];
  byte_t ch;
  int fd;
  ssize_t r;

  errno = error_io;
  fd = dt->s;

  if (!x->revents) {
    if (taia_less(when, &dt->deadline)) return 0;
    errno = error_timeout;
    if (dt->tcpstate == 0) {
      return next_udp(dt);
    }
    return next_tcp(dt);
  }

  if (dt->tcpstate == 0) {
/*
    have attempted to send UDP query to each server udploop times
    have sent query to curserver on UDP socket s
*/
    r = recv(fd, udp_buf, sizeof(udp_buf), 0);
    if (r <= 0) {
      if (errno == error_connrefused) {
        if (dt->udploop == 2) return 0;
      }
      return next_udp(dt);
    }
    if (r + 1 > (int)sizeof(udp_buf)) return 0;

    switch (irrelevant(dt, udp_buf, (unsigned int)r)) {
      case -1: return -1;  /* fatal */
      case 0: break;
      default: return 0;
    }
    if (server_wants_tcp(udp_buf, (unsigned int)r)) {
      return dns4_transmit_first_tcp(dt);
    }
    if (server_failed(udp_buf, (unsigned int)r)) {
      if (dt->udploop == 2) return 0;
      return next_udp(dt);
    }
    dns_socket_free(dt);
    dns4_transmit_packet_free(dt);
    dt->packetlen = (unsigned int)r;
    dt->packet = alloc(dt->packetlen);
    if (!dt->packet) {
      dns4_transmit_free(dt);
      return -1;  /* fatal */
    }
    byte_copy(dt->packet, dt->packetlen, udp_buf);
    dns4_transmit_query_free(dt);
    return 1;
  }

  if (dt->tcpstate == 1) {
/*
    have sent connection attempt to curserver on TCP socket s
    pos not defined
*/
    if (!socket_connected(fd)) {
      return next_tcp(dt);
    }
    dt->pos = 0;
    dt->tcpstate = 2;
    return 0;
  }

  if (dt->tcpstate == 2) {
/*
    have connection to curserver on TCP socket s
    have sent pos bytes of query
*/
    r = write(fd, dt->query + dt->pos, dt->querylen - dt->pos);
    if (r <= 0) {
      return next_tcp(dt);
    }
    dt->pos += (unsigned int)r;
    if (dt->pos == dt->querylen) {
      taia_now(&now);
      taia_uint(&dt->deadline, 10);
      taia_add(&dt->deadline, &dt->deadline, &now);
      dt->tcpstate = 3;
    }
    return 0;
  }

  if (dt->tcpstate == 3) {
/*
    have sent entire query to curserver on TCP socket s
    pos not defined
*/
    r = read(fd, &ch, 1);
    if (r <= 0) {
      return next_tcp(dt);
    }
    dt->packetlen = ch;
    dt->tcpstate = 4;
    return 0;
  }

  if (dt->tcpstate == 4) {
/*
    have sent entire query to curserver on TCP socket s
    pos not defined
    have received one byte of packet length into packetlen
*/
    r = read(fd, &ch, 1);
    if (r <= 0) {
      return next_tcp(dt);
    }
    dt->packetlen <<= 8;
    dt->packetlen += ch;
    dt->tcpstate = 5;
    dt->pos = 0;
    dt->packet = alloc(dt->packetlen);
    if (!dt->packet) {
      dns4_transmit_free(dt);
      return -1;  /* fatal */
    }
    return 0;
  }

  if (dt->tcpstate == 5) {
/*
    have sent entire query to curserver on TCP socket s
    have received entire packet length into packetlen
    packet is allocated
    have received pos bytes of packet
*/
    r = read(fd, dt->packet + dt->pos, dt->packetlen - dt->pos);
    if (r <= 0) {
      return next_tcp(dt);
    }
    dt->pos += (unsigned int)r;
    if (dt->pos < dt->packetlen) return 0;

    dns_socket_free(dt);
    switch (irrelevant(dt, dt->packet, dt->packetlen)) {
      case -1: return -1;  /* fatal */
      case 0: break;
      default: return next_tcp(dt);
    }
    if (server_wants_tcp(dt->packet, dt->packetlen)) {
      return next_tcp(dt);
    }
    if (server_failed(dt->packet, dt->packetlen)) {
      return next_tcp(dt);
    }

    dns4_transmit_query_free(dt);
    return 1;
  }

  return 0;
}
