#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/byte.h>
#include <nemo/alloc.h>
#include <nemo/error.h>
#include <nemo/socket.h>
#include <nemo/ndelay.h>
#include <nemo/unix.h>
#include <nemo/uint16.h>

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

static int socket_tcp53 = -1;

unsigned int tcpclient_active = 0;  /* global */

static client *t_connected_list_head = 0;
static client *t_datasize_list_head = 0;
static client *t_payload_list_head = 0;
static client *t_active_list_head = 0;
static client *t_response_list_head = 0;

static client *t_ioquery_list_head = 0;


#include "tcpclient.c"


void tcpclient_setup_socket(const ip6_address *ip_incoming)
{
  socket_tcp53 = socket6_tcp();
  if (socket_tcp53 < 0) {
    die_tcpsocket();
  }
  if (socket6_bind_reuse(socket_tcp53, ip_incoming, 53) < 0) {
    die_tcpsocket();
  }
}

static void t_close(client **head, client *x)
{
  log6_tcpclose(&x->ip, x->port);
  close(x->tcp);
  t_free(head, x);
}

static void t_drop(client **head, client *x)
{
  log6_drop_query(x->query_number, response_len, &x->ip, x->port, &x->id, x->loop);
  t_close(head, x);
}

void tcpclient_do_response(client *x)
{
  ssize_t r;

  if (x->io->revents) {
    t_set_timeout(x);
  }
  r = write(x->tcp, x->buf + x->pos, x->len - x->pos);
  if (r <= 0) {  /* error */
    t_drop_responding(x);
    return;
  }
  x->pos += (unsigned int)r;
  if (x->pos == x->len) {  /* finished */
    log6_query_done(x->query_number, response_len, &x->ip, x->port, &x->id, x->loop, response[3] & 15);
    t_close_responding(x);
  }
}

static void t_start_active(client *x)
{
  x->query_number = ++num_queries;
  client_move(x, &t_payload_list_head, &t_active_list_head);

  if (!packetquery(x->buf, x->len, &x->name, &x->type, &x->class, &x->id, &x->flag_edns0, &x->udp_size)) {
    log6_rejected_packet(&x->ip, x->port);
    tcpclient_drop_active(x);
    return;
  }

  log6_query(x->query_number, &x->ip, x->port, &x->id, &x->name, &x->type, x->flag_edns0, x->udp_size);

  if (t_try_answer(x)) return;
  query_start(x, &x->type, &x->name, client_do_cname(&x->type));
}

void tcpclient_start(void)
{
  client *x;

  x = t_new();
  if (!x) {  /* all in use, get oldest from any list */
    x = t_recycle_oldest();
  }

  x->ctype = TCP_CLIENT;
  taia_now(&x->start);

  x->tcp = socket6_accept(socket_tcp53, &x->ip, &x->port);
  if (x->tcp < 0) {
    t_free_connected(x);
    return;
  }
  if (x->port < 1024 && x->port != 53) {
    log_rejected_source_port(x->port);
    t_drop_connected(x);
    return;
  }
  if (!okclient6(&x->ip)) {
    log6_rejected_source_ip(&x->ip);
    t_drop_connected(x);
    return;
  }
  if (ndelay_on(x->tcp) < 0) {  /* Linux bug */
    t_drop_connected(x);
    return;
  }

  x->io = 0;
  x->query_number = 0;
  t_set_timeout(x);

  log6_tcpopen(&x->ip, x->port);

  t_start_datasize(x);
}
