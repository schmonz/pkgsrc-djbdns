#include <nemo/error.h>
#include <nemo/socket.h>

#include "dnscache.h"
#include "response.h"
#include "okclient.h"
#include "log.h"
#include "dn_vector.h"
#include "cache.h"
#include "die.h"

#include "client6.h"
#include "ioquery6.h"
#include "query6.h"
#include "tcpclient6.h"
#include "udpclient6.h"

/* #define DEBUG 1 */
#include "debug.h"

static int socket_udp53 = -1;

unsigned int udpclient_active = 0;  /* global */

static client *u_active_list_head = 0;
static client *u_ioquery_list_head = 0;


#include "udpclient.c"


void udpclient_setup_socket(const ip6_address *ip_incoming)
{
  socket_udp53 = socket6_udp();
  if (socket_udp53 < 0) die_udpsocket();
  if (socket6_bind_reuse(socket_udp53, ip_incoming, 53) < 0) die_udpsocket();
}

static void u_drop(client **head, client *x)
{
  response_query(&x->name, &x->type, &x->class);
  response_id(&x->id);
  response_servfail();
  response_send6(socket_udp53, &x->ip, x->port);

  log6_drop_query(x->query_number, response_len, &x->ip, x->port, &x->id, x->loop);
  u_free(head, x);
}

static void u_respond(client *x)
{
  response_id(&x->id);
  if (x->flag_edns0) {
    if (response_opt_start(x->udp_size, DNS_RCODE_NOERROR)) {
      response_opt_finish();
    }
    else {
      response_servfail();
    }
  }
  if (response_len > x->udp_size) {
    response_tc();
  }
  response_send6(socket_udp53, &x->ip, x->port);

  log6_query_done(x->query_number, response_len, &x->ip, x->port, &x->id, x->loop, response[3] & 15);
  u_free_active(x);
}

static byte_t buf[DNS_UDP_SIZE_MAX];

void udpclient_start(void)
{
  unsigned int flag_edns0;
  unsigned int udp_size;
  ip6_address ip;
  uint16_t port;
  dns_id id;
  dns_type type;
  dns_class class;
  client *x;
  int len;

  len = socket6_recv(socket_udp53, buf, sizeof buf, &ip, &port);
  if (len < 0) return;
  if (len >= (int)sizeof(buf)) return;
  if (port < 1024 && port != 53) {
    log_rejected_source_port(port);
    return;
  }
  if (!okclient6(&ip)) {
    log6_rejected_source_ip(&ip);
    return;
  }

  if (!packetquery(buf, (unsigned int)len, &d, &type, &class, &id, &flag_edns0, &udp_size)) {
    log6_rejected_packet(&ip, port);
    return;
  }

  x = u_new();
  if (!x) {  /* all in use, get oldest from any list */
    x = u_recycle_oldest();
  }

  if (!dns_domain_copy(&x->name, &d)) die_nomem();
  taia_now(&x->start);
  x->ctype = UDP_CLIENT;
  x->ip = ip;
  x->port = port;
  x->type = type;
  x->class = class;
  x->id = id;
  x->flag_edns0 = flag_edns0;
  x->udp_size = udp_size;
  x->query_number = ++num_queries;

  log6_query(x->query_number, &ip, port, &id, &d, &type, flag_edns0, udp_size);

  if (u_try_answer(x)) return;
  query_start(x, &type, &d, client_do_cname(&type));
}
