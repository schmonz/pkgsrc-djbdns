#include <nemo/byte.h>
#include <nemo/error.h>

#include "dnscache.h"
#include "log.h"
#include "dn_vector.h"
#include "cache.h"
#include "die.h"

#include "client4.h"
#include "ioquery4.h"
#include "query4.h"
#include "tcpclient4.h"
#include "udpclient4.h"

static ioquery in_progress[MAX_IOQUERY];

static ioquery *ioq_free_list_head;
static ioquery *ioq_active_list_head;

static const ip4_address *local_ip;


#include "ioquery.c"


void ioquery_setup(const ip4_address *ip)
{
  register unsigned int i;
  for (i = 0; i < MAX_IOQUERY; i++) {
    dns4_transmit_init(&(in_progress[i].dt));
  }
  for (i = 0; i < MAX_IOQUERY - 1; i++) {
    in_progress[i].next = &in_progress[i + 1];
  }
  ioq_free_list_head = &in_progress[0];
  local_ip = ip;
}

void ioquery_free(ioquery *x)
{
  ioquery *t;
  ioquery *p;

  t = ioq_active_list_head;
  p = 0;
  while (t) {
    if (t == x) break;
    p = t;
    t = t->next;
  }
  if (!t) return;  /* not found */
  if (p) {
    p->next = x->next;
  }
  else {
    ioq_active_list_head = x->next;
  }
  x->next = ioq_free_list_head;
  ioq_free_list_head = x;
  dns_domain_free(&x->name);
  dns_domain_free(&x->control);
  dns4_transmit_free(&x->dt);
  x->edns0 = 0;
  x->active = 0;
  x->io = 0;
}

unsigned int ioquery_start(query *q,
                            ip4_vector *servers,
                            unsigned int flag_recursive,
                            unsigned int flag_edns0,
                            const dns_domain *name,
                            const dns_type *type,
                            const dns_domain *control)
{
  ioquery *t;

  t = ioq_active_list_head;
  while (t) {
    if (ioquery_key_equal(t, name, type, control, flag_edns0)) {
      ioquery_add_query(t, q);
      log_tx_piggyback(q->client->query_number, name, type, control);
      q->ioq = t;
      return 1;
    }
    t = t->next;
  }
  t = ioquery_new();
  ioquery_add_query(t, q);
  if (!dns_domain_copy(&t->name, name)) die_nomem();
  if (!dns_domain_copy(&t->control, control)) die_nomem();
  dns_type_copy(&t->type, type);
  t->edns0 = flag_edns0;
  q->ioq = t;

  log4_tx(q->client->query_number, name, type, control, servers);

  if (flag_edns0) {
    if (dns4_transmit_start_edns0(&t->dt, servers, flag_recursive, name, type, local_ip) < 0) {
      log_tx_error(q->client->query_number);
      return 0;
    }
    return 1;
  }

  if (dns4_transmit_start(&t->dt, servers, flag_recursive, name, type, local_ip) < 0) {
    log_tx_error(q->client->query_number);
    return 0;
  }
  return 1;
}

void ioquery_io(ioquery *x, struct taia *deadline)
{
  dns4_transmit_io(&x->dt, x->io, deadline);
}

int ioquery_get(ioquery *x, const struct taia *when)
{
  int r;
  r = dns4_transmit_get(&x->dt, x->io, when);
  if (r < 0) {        	/* fatal */
    if (errno == error_nomem) die_nomem();
    ioquery_drop(x);
    return 0;
  }
  if (r == 0) return 0;		/* must wait for i/o */
  if (r == 1) return 1;		/* have packet */
  die_getioquery();		/* bug */
  return 0;
}
