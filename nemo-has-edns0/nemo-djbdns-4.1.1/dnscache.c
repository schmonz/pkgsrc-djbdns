#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/env.h>
#include <nemo/exit.h>
#include <nemo/scan.h>
#include <nemo/byte.h>
#include <nemo/fmt.h>
#include <nemo/alloc.h>
#include <nemo/ip4.h>
#include <nemo/socket.h>
#include <nemo/ndelay.h>
#include <nemo/unix.h>
#include <nemo/sig.h>
#include <nemo/macro_unused.h>

#include "dnscache.h"
#include "ignore_ip_init.h"
#include "response.h"
#include "cache.h"
#include "log.h"
#include "okclient.h"
#include "roots.h"
#include "droproot.h"
#include "dn_vector.h"
#include "die.h"

#include "client4.h"
#include "ioquery4.h"
#include "query4.h"
#include "tcpclient4.h"
#include "udpclient4.h"

uint64_t num_queries = 0;  /* global */
unsigned int edns0_enabled = 0;  /* global */

static iopause_fd io[3 + MAX_UDP + MAX_TCP];
static iopause_fd *udp53io;
static iopause_fd *tcp53io;

static void doit(void)
{
  ioquery *x;
  ioquery *next_ioquery;
  client *z;
  client *next_client;
  struct taia deadline;
  struct taia stamp;
  unsigned int iolen;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline, IO_TTL);
    taia_add(&deadline, &deadline, &stamp);

    iolen = 0;

    udp53io = io + iolen++;
    udp53io->fd = udpclient_socket();
    udp53io->events = IOPAUSE_READ;

    tcp53io = io + iolen++;
    tcp53io->fd = tcpclient_socket();
    tcp53io->events = IOPAUSE_READ;
/*
    add any external queries to io polling
*/
    for (x = ioquery_active_list_head(); x; x = x->next) {
      x->io = io + iolen++;
      ioquery_io(x, &deadline);
    }
/*
    set up test for tcp datasize io
*/
    for (z = tcpclient_datasize_list_head(); z; z = z->next) {
      z->io = io + iolen++;
      z->io->fd = z->tcp;
      z->io->events = IOPAUSE_READ;
      if (taia_less(&z->timeout, &deadline)) {
	deadline = z->timeout;
      }
    }
/*
    set up test for tcp payload io
*/
    for (z = tcpclient_payload_list_head(); z; z = z->next) {
      z->io = io + iolen++;
      z->io->fd = z->tcp;
      z->io->events = IOPAUSE_READ;
      if (taia_less(&z->timeout, &deadline)) {
	deadline = z->timeout;
      }
    }
/*
    set up test for tcp response io
*/
    for (z = tcpclient_response_list_head(); z; z = z->next) {
      z->io = io + iolen++;
      z->io->fd = z->tcp;
      z->io->events = IOPAUSE_WRITE;
      if (taia_less(&z->timeout, &deadline)) {
	deadline = z->timeout;
      }
    }
/*
    wait for any io
*/
    iopause(io, iolen, &deadline, &stamp);
/*
    collect any responses from other name servers
*/
    for (x = ioquery_active_list_head(); x; x = next_ioquery) {
      next_ioquery = x->next;  /* x may be moved by ioquery_drop(), etc */
      if (ioquery_get(x, &stamp) == 1) {
        ioquery_havepacket(x);
      }
    }
/*
    continue sending tcp response
*/
    for (z = tcpclient_response_list_head(); z; z = next_client) {
      next_client = z->next;  /* z may be moved by tcpclient_do_response() */
      if (tcpclient_ioready(z, &stamp)) {
        tcpclient_do_response(z);
      }
    }
/*
    continue receiving tcp payload
*/
    for (z = tcpclient_payload_list_head(); z; z = next_client) {
      next_client = z->next;  /* z may be moved by tcpclient_do_payload() */
      if (tcpclient_ioready(z, &stamp)) {
        tcpclient_do_payload(z);
      }
    }
/*
    continue receiving tcp datasize
*/
    for (z = tcpclient_datasize_list_head(); z; z = next_client) {
      next_client = z->next;  /* z may be moved by tcpclient_do_datasize() */
      if (tcpclient_ioready(z, &stamp)) {
        tcpclient_do_datasize(z);
      }
    }
/*
    test for new udp query
*/
    if (udp53io->revents) {
      udpclient_start();
    }
/*
    text for new tcp query
*/
    if (tcp53io->revents) {
      tcpclient_start();
    }
/*
    scan for any udp queries that can be retried
*/
    for (z = udpclient_active_list_head(); z; z = next_client) {
      next_client = z->next;  /* z may be moved by udpclient_try() */
      udpclient_try(z);
    }
/*
    scan for any tcp queries that can be retried
*/
    for (z = tcpclient_active_list_head(); z; z = next_client) {
      next_client = z->next;  /* z may be moved by tcpclient_try() */
      tcpclient_try(z);
    }
  }
}

int main(int argc __UNUSED__, char **argv)
{
  char seed[128];
  const char *x;
  uint32_t minttl;
  unsigned int len;
  unsigned int cachesize;
  ip4_address my_ip_outgoing;
  ip4_address my_ip_incoming;

  PROGRAM = *argv;
  minttl = 0;
  sig_pipeignore();
  x = env_get("IP");
  if (!x) die_env("IP");
  if (!ip4_scan(&my_ip_incoming, x)) die_parse("$IP", x);

  udpclient_setup_socket(&my_ip_incoming);
  tcpclient_setup_socket(&my_ip_incoming);

  droproot();

  read(0, seed, sizeof(seed));
  dns_random_init(seed);
  close(0);

  x = env_get("IPSEND");
  if (!x) die_env("IPSEND");
  if (!ip4_scan(&my_ip_outgoing, x)) die_parse("$IPSEND", x);

  x = env_get("MINTTL");
  if (x) {
    len = scan_uint32(x, &minttl);
    if (!len || x[len]) die_parse("$MINTTL", x);
  }

  x = env_get("CACHESIZE");
  if (!x) die_env("CACHESIZE");
  len = scan_uint(x, &cachesize);
  if (!len || x[len]) die_parse("$CACHESIZE", x);
  if (!cache_init(cachesize, minttl)) die1("not enough memory for cache");

  if (env_get("HIDETTL")) {
    response_hidettl();
  }
  if (env_get("FORWARDONLY")) {
    query_forwardonly();
  }
  if (env_get("EDNS0")) {
    edns0_enabled = 1;
  }

  ignore_ip4_init();
  ignore_ip6_init();
  roots4_init();
  ioquery_setup(&my_ip_outgoing);
  query_setup();
  client_setup();
  udpclient_setup();
  tcpclient_setup();

  log_startup(cachesize, minttl, edns0_enabled);

  doit();
  return 0;  /* lint */
}
