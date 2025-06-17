/*
	This is included by:	query4.c
				query6.c
*/

void query_setup(void)
{
  register unsigned int i;
  for (i = 0; i < MAX_QUERY - 1; i++) {
    q_list[i].next = &q_list[i + 1];
  }
  q_free_list_head = &q_list[0];
}

static query *q_new(query **head)
{
  query *new;
  if (!q_free_list_head) die_newquery();  /* fatal */

  /* remove query from front of free list */
  new = q_free_list_head;
  q_free_list_head = new->next;

  /* add it to front of unresolved list */
  new->next = *head;
  *head = new;

  return new;
}

static void free_ns(query *z)
{
  dn_vector_free(&z->ns);
}

static void q_cleanup(query *z)
{
  z->client = 0;
  z->resolve_cname = 0;
  z->retry_glueless = 0;
  dns_type_zero(&z->type);
  dns_class_zero(&z->class);
  dns_domain_free(&z->name);
  dns_domain_free(&z->control);
  free_ns(z);
  free_servers(z);
  if (z->ioq) {
    ioquery_remove_query(z->ioq, z);
    z->ioq = 0;
  }
}

static void q_free(query **head, query *z)
{
  query *t;
  query *p;

  q_cleanup(z);
  t = *head;
  p = 0;
  while (t) {
    if (t == z) break;
    p = t;
    t = t->next;
  }
  if (!t) return;  /* not found */
  if (p) {
    p->next = z->next;
  }
  else {
    *head = z->next;
  }
  z->next = q_free_list_head;
  q_free_list_head = z;
}

void query_free_list(query **head)
{
  query *t;
  query *p;

  t = *head;
  p = 0;
  while (t) {
    q_cleanup(t);
    p = t;
    t = t->next;
  }
  if (!p) return;  /* empty list */
  p->next = q_free_list_head;
  q_free_list_head = *head;
  *head = 0;
}

void query_forwardonly(void)
{
  flag_forwardonly = 1;
}

static void move_to_ioquery_list(query *z)
{
  client_to_ioquery_list(z->client);
}

void query_start(client *x, const dns_type *type, const dns_domain *name, unsigned int do_cname)
{
  query *newq;

  newq = q_new(&x->qlist);

  newq->client = x;
  newq->ioq = 0;
  newq->resolve_cname = do_cname;
  newq->retry_glueless = 0;

  if (!dns_domain_copy(&newq->name, name)) die_nomem();
  dns_type_copy(&newq->type, type);
  dns_class_copy(&newq->class, &x->class);
}

void query_end(query *z)
{
  if (!z) return;
  q_free(&z->client->qlist, z);
}

void query_drop(query *z)
{
  if (!z) return;
  q_free(&z->client->qlist, z);
}

/*
unsigned int query_peek(const query *z)
{
  static ip4_vector ip_servers = IP4_VECTOR;
  static dn_vector dn_servers = DN_VECTOR;
  dns_domain dn;
  register unsigned int len;

  if (flag_forwardonly) return 0;
  dn = z->name;
  for (;;) {
    if (!z) break;
    if (roots4(&dn, &ip_servers)) break;
    if (cache_get_rr_ns(&dn, &dn_servers) == CACHE_HIT) return 1;
    len = dn.data[0];
    if (!len) break;
    len++;
    dn.data += len;
    dn.len -= len;
    z = z->next;
  }
  return 0;
}

unsigned int query_peek(const query *z)
{
  static dns_domain qname = DNS_DOMAIN;
  static dns_domain cname = DNS_DOMAIN;
  register cache_t r_cache;

  for (;;) {
    if (!z) break;
    if (!dns_domain_copy(&qname, &z->name)) die_nomem();
    for (;;) {
      if (cache_get_rr_cname(&qname, &cname) != CACHE_HIT) break;
      if (!dns_domain_copy(&qname, &cname)) die_nomem();
    }
    r_cache = cache_test_rr(&z->type, &qname);
    if (r_cache != CACHE_MISS && r_cache != CACHE_EXPIRED) return 1;
    z = z->next;
  }
  return 0;
}
*/
