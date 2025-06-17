/*
	This is included by:	ioquery4.c
				ioquery6.c
*/

ioquery *ioquery_active_list_head(void)
{
  return ioq_active_list_head;
}

static int ioquery_key_equal(ioquery *q, const dns_domain *qname, const dns_type *qtype, const dns_domain *control, unsigned int flag_edns0)
{
  return
    dns_type_equal(&q->type, qtype) &&
    dns_domain_equal(&q->name, qname) &&
    dns_domain_equal(&q->control, control) &&
    q->edns0 == flag_edns0;
}

static ioquery *ioquery_new(void)
{
  ioquery *new;
  if (!ioq_free_list_head) die_newioquery();  /* fatal */

  /* remove query from front of free list */
  new = ioq_free_list_head;
  ioq_free_list_head = new->next;

  /* add it to front of active list*/
  new->next = ioq_active_list_head;
  ioq_active_list_head = new;

  return new;
}

void ioquery_signal_clients(ioquery *x)
{  /* mark all affected queries */
  query *q;
  unsigned int i;
  for (i = 0; i < x->active; i++) {
    q = x->queries[i];
    if (q) {  /* if zero -> query dropped (timeout or quota overflow) */
      client_end_ioquery(q->client);
    }
  }
  x->active = 0;
}

static void ioquery_drop(ioquery *x)
{
  cache_mark(&x->type, &x->name, CACHE_SERVFAIL, 0);
  ioquery_signal_clients(x);
  ioquery_free(x);
}

void ioquery_remove_query(ioquery *x, const query *q)
{
  register unsigned int i;
  for (i = 0; i < x->active; i++) {
    if (x->queries[i] == q) {
      x->queries[i] = 0;
      break;
    }
  }
}

static void ioquery_add_query(ioquery *x, query *q)
{
  x->queries[x->active++] = q;
}

