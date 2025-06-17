/*
        This is included by:    tcpclient4.c
                                tcpclient6.c
*/

static void t_close(client **head, client *x);
static void t_start_active(client *x);
static void t_drop(client **head, client *x);

client *tcpclient_active_list_head(void)
{
  return t_active_list_head;
}

client *tcpclient_datasize_list_head(void)
{
  return t_datasize_list_head;
}

client *tcpclient_payload_list_head(void)
{
  return t_payload_list_head;
}

client *tcpclient_response_list_head(void)
{
  return t_response_list_head;
}

int tcpclient_socket(void)
{
  return socket_tcp53;
}

void tcpclient_setup(void)
{
  if (socket_listen(socket_tcp53, 20) < 0) die_tcpsocket();
}

static client *t_new(void)
{
  if (tcpclient_active == MAX_TCP) return 0;
  tcpclient_active++;
  return client_new(&t_connected_list_head);
}

static void t_free(client **head, client *x)
{
  tcpclient_active--;
  client_free(head, x);
}

static void t_free_connected(client *x)
{
  t_free(&t_connected_list_head, x);
}

static void t_close_responding(client *x)
{
  t_close(&t_response_list_head, x);
}

static void t_drop_connected(client *x)
{
  t_drop(&t_connected_list_head, x);
}

void tcpclient_drop_active(client *x)
{
  t_drop(&t_active_list_head, x);
}

static void t_drop_datasize(client *x)
{
  t_drop(&t_datasize_list_head, x);
}

static void t_drop_payload(client *x)
{
  t_drop(&t_payload_list_head, x);
}

static void t_drop_responding(client *x)
{
  t_drop(&t_response_list_head, x);
}

static client *t_recycle_oldest(void)
{
  client *x;
  client *y;
  client **yhead;

  y = client_find_oldest(t_connected_list_head);
  yhead = &t_connected_list_head;

  x = client_find_oldest(t_active_list_head);
  if (!y || (x && taia_less(&x->start, &y->start))) {
    y = x;
    yhead = &t_active_list_head;
  }

  x = client_find_oldest(t_datasize_list_head);
  if (!y || (x && taia_less(&x->start, &y->start))) {
    y = x;
    yhead = &t_datasize_list_head;
  }

  x = client_find_oldest(t_datasize_list_head);
  if (!y || (x && taia_less(&x->start, &y->start))) {
    y = x;
    yhead = &t_datasize_list_head;
  }

  x = client_find_oldest(t_ioquery_list_head);
  if (!y || (x && taia_less(&x->start, &y->start))) {
    y = x;
    yhead = &t_ioquery_list_head;
  }

  x = client_find_oldest(t_response_list_head);
  if (!y || (x && taia_less(&x->start, &y->start))) {
    y = x;
    yhead = &t_response_list_head;
  }
  if (!y) die_newtcpclient();  /* this should never happen */

  errno = error_timeout;
  t_drop(yhead, y);  /* will put oldest on free list */
  return t_new();
}

static void t_set_timeout(client *x)
{
  struct taia now;
  taia_now(&now);
  taia_uint(&x->timeout, 10);
  taia_add(&x->timeout, &x->timeout, &now);
}

static void t_start_response(client *x)
{
  client_buf_free(x);
  x->buf = alloc(response_len + 2);
  if (!x->buf) die_nomem();

  response_id(&x->id);
  uint16_pack_big((uint16_t)response_len, x->buf);
  byte_copy(x->buf + 2, response_len, response);

  x->len = response_len + 2;
  x->pos = 0;

  client_move(x, &t_active_list_head, &t_response_list_head);
}

void tcpclient_end_ioquery(client *x)
{
  client_move(x, &t_ioquery_list_head, &t_active_list_head);
}

void tcpclient_to_ioquery_list(client *x)
{
  client_move(x, &t_active_list_head, &t_ioquery_list_head);
}

static unsigned int t_try_answer(client *x)
{
  register query_cache_t r;
  r = client_answer(x);
  if (r == R_FAIL) {
    log_local_fail(&x->name, &x->type, "client answer error");
    tcpclient_drop_active(x);
    return 1;
  }
  if (r == R_FOUND_OK) {
    t_start_response(x);
    return 1;
  }
  return 0;
}

static unsigned int t_try_cname(dns_domain *qname)
{
  static dns_domain cname = DNS_DOMAIN;
  register cache_t status;
  unsigned int i;

  for (i = 0; i < MAX_ALIAS; i++) {
    status = cache_get_rr_cname(qname, &cname);
    if (status == CACHE_EXPIRED) return 2;  /* retry */
    if (status != CACHE_HIT) return 0;  /* end of search */
    if (!dns_domain_copy(qname, &cname)) die_nomem();
  }
  return 1;  /* fail */
}

void tcpclient_try(client *x)
{
  static dns_domain qname = DNS_DOMAIN;
  register query *q;
  register query_event_t r_event;
  register cache_t r_cache;
  unsigned int r_cname;
  unsigned int do_cname;

  while (++x->loop < MAX_LOOP) {
    q = x->qlist;
    if (!q) {
      if (t_try_answer(x)) return;
      query_start(x, &x->type, &x->name, client_do_cname(&x->type));
      continue;
    }
    if (!dns_domain_copy(&qname, &q->name)) die_nomem();
    do_cname = client_do_cname(&q->type);
    if (do_cname) {
      r_cname = t_try_cname(&qname);
      if (r_cname == 1) {  /* fail */
	log_local_fail(&x->name, &x->type, "too many CNAMEs for request");
	tcpclient_drop_active(x);
	return;
      }
      if (r_cname == 2) {  /* retry expired CNAME */
        cache_mark(dns_t_cname, &qname, CACHE_MISS, 0);
        query_start(x, &q->type, &qname, 1);
        continue;
      }
      /* end of CNAME search */
    }
    r_cache = cache_test_rr(&q->type, &qname);
    if (r_cache != CACHE_MISS && r_cache != CACHE_EXPIRED) {
      query_end(q);
      continue;
    }
    if (!dns_domain_equal(&qname, &q->name)) {
      query_start(x, &q->type, &qname, do_cname);
      continue;
    }
    r_event = query_try(q);
    if (r_event == R_QUERY_EVENT_IOQUERY) return;  /* new ioquery, moved to ioquery list */
    if (r_event == R_QUERY_EVENT_FAIL) {
      tcpclient_drop_active(x);
      return;
    }
    /* R_QUERY_EVENT_NEW, R_QUERY_EVENT_RETRY */  /* loop again */
  }
  log_local_fail(&x->name, &x->type, "too many queries for request");
  tcpclient_drop_active(x);
}

void tcpclient_do_payload(client *x)
{
  byte_t ch;
  ssize_t r;

  if (x->io->revents) {
    t_set_timeout(x);
  }
  r = read(x->tcp, &ch, 1);
  if (r == 0) {
    errno = error_pipe;
    t_drop_payload(x);
    return;
  }
  if (r < 0) {
    errno = error_pipe;
    t_drop_payload(x);
    return;
  }

  x->buf[x->pos++] = ch;
  if (x->pos < x->len) return;

  t_start_active(x);
}

static void t_start_payload(client *x)
{
  client_move(x, &t_datasize_list_head, &t_payload_list_head);

  if (!x->len) {
    errno = error_proto;
    t_drop_payload(x);
    return;
  }

  x->buf = alloc(x->len);
  if (!x->buf) die_nomem();

  x->pos = 0;
}

void tcpclient_do_datasize(client *x)
{
  byte_t ch;
  ssize_t r;

  if (x->io->revents) {
    t_set_timeout(x);
  }
  r = read(x->tcp, &ch, 1);
  if (r == 0) {
    errno = error_pipe;
    t_drop_datasize(x);
    return;
  }
  if (r < 0) {
    errno = error_pipe;
    t_drop_datasize(x);
    return;
  }

  x->len <<= 8;
  x->len |= (byte_t) ch;
  x->pos++;

  if (x->pos == 2) {
    t_start_payload(x);
  }
}

static void t_start_datasize(client *x)
{
  client_move(x, &t_connected_list_head, &t_datasize_list_head);

  x->pos = 0;
  x->len = 0;
}

unsigned int tcpclient_ioready(const client *x, const struct taia *stamp)
{
  if (x->io && x->io->revents) return 1;
  return taia_less(&x->timeout, stamp);
}
