/*
        This is included by:    udpclient4.c
                                udpclient6.c
*/

static dns_domain d = DNS_DOMAIN;

static void u_drop(client **head, client *x);
static void u_respond(client *x);

client *udpclient_active_list_head(void)
{
  return u_active_list_head;
}

int udpclient_socket(void)
{
  return socket_udp53;
}

void udpclient_setup(void)
{
  socket_try_reserve_in(socket_udp53, 131072);
}

static client *u_new(void)
{
  if (udpclient_active == MAX_UDP) return 0;
  udpclient_active++;
  return client_new(&u_active_list_head);
}

static void u_free(client **head, client *x)
{
  udpclient_active--;
  client_free(head, x);
}

static void u_free_active(client *x)
{
  u_free(&u_active_list_head, x);
}

void udpclient_drop_active(client *x)
{
  u_drop(&u_active_list_head, x);
}

static client *u_recycle_oldest(void)
{
  client *x;
  client *y;
  client **yhead;

  y = client_find_oldest(u_ioquery_list_head);
  yhead = &u_ioquery_list_head;

  x = client_find_oldest(u_active_list_head);
  if (!y || (x && taia_less(&x->start, &y->start))) {
    y = x;
    yhead = &u_active_list_head;
  }

  if (!y) die_newudpclient();  /* this should never happen */

  errno = error_timeout;
  u_drop(yhead, y);  /* will put oldest on free list */
  return u_new();
}

void udpclient_end_ioquery(client *x)
{
  client_move(x, &u_ioquery_list_head, &u_active_list_head);
}

void udpclient_to_ioquery_list(client *x)
{
  client_move(x, &u_active_list_head, &u_ioquery_list_head);
}

static unsigned int u_try_answer(client *x)
{
  register query_cache_t r;
  r = client_answer(x);
  if (r == R_FAIL) {
    log_local_fail(&x->name, &x->type, "client answer error");
    udpclient_drop_active(x);
    return 1;
  }
  if (r == R_FOUND_OK) {
    u_respond(x);
    return 1;
  }
  return 0;
}

static unsigned int u_try_cname(dns_domain *name)
{
  static dns_domain cname = DNS_DOMAIN;
  register cache_t status;
  unsigned int i;

  for (i = 0; i < MAX_ALIAS; i++) {
    status = cache_get_rr_cname(name, &cname);
    if (status == CACHE_EXPIRED) return 2;  /* expired */
    if (status != CACHE_HIT) return 0;  /* end of search */
    if (!dns_domain_copy(name, &cname)) die_nomem();
  }
  return 1;  /* fail */
}

void udpclient_try(client *x)
{
  static dns_domain qname = DNS_DOMAIN;
  register dns_type *qtype;
  register query *q;
  register query_event_t r_event;
  register cache_t r_cache;
  unsigned int r_cname;
  unsigned int do_cname;

  while (++x->loop < MAX_LOOP) {
    debug_putuint("udpclient_try:loop", x->loop);
    q = x->qlist;
    if (!q) {
      if (u_try_answer(x)) return;
      query_start(x, &x->type, &x->name, client_do_cname(&x->type));
      continue;
    }
    if (!dns_domain_copy(&qname, &q->name)) die_nomem();
    qtype = &q->type;
    debug_puttype("udpclient_try:x->type", &x->type);
    debug_puttype("udpclient_try:qtype", qtype);
    debug_putdomain("udpclient_try:qname(<CNAME)", &qname);
    do_cname = client_do_cname(qtype);
    if (do_cname) {
      r_cname = u_try_cname(&qname);
      debug_putuint("udpclient_try:u_try_cname", r_cname);
      if (r_cname == 1) {  /* fail */
	log_local_fail(&x->name, &x->type, "too many CNAMEs for request");
	udpclient_drop_active(x);
	return;
      }
      if (r_cname == 2) {  /* expired CNAME, retry */
        cache_mark(dns_t_cname, &qname, CACHE_MISS, 0);
        query_start(x, qtype, &qname, 1);
        continue;
      }
      /* end of CNAME search */
    }
    debug_putdomain("udpclient_try:qname(>CNAME)", &qname);
    r_cache = cache_test_rr(qtype, &qname);
    debug_putuint("udpclient_try:cache_test_rr", r_cache);
    if (r_cache != CACHE_MISS && r_cache != CACHE_EXPIRED) {
      query_end(q);
      continue;
    }
    if (!dns_domain_equal(&qname, &q->name)) {
      query_start(x, qtype, &qname, do_cname);
      continue;
    }
    r_event = query_try(q);
    if (r_event == R_QUERY_EVENT_IOQUERY) return;  /* new ioquery, moved to ioquery list */
    if (r_event == R_QUERY_EVENT_FAIL) {
      udpclient_drop_active(x);
      return;
    }
    /* R_QUERY_EVENT_NEW, R_QUERY_EVENT_RETRY */  /* loop again */
  }
  log_local_fail(&x->name, &x->type, "too many queries for request");
  udpclient_drop_active(x);
}
