/*
	This is included by:	client4.c
				client6.c
*/

void client_setup(void)
{
  register unsigned int i;
  for (i = 0; i < MAX_IOQUERY - 1; i++) {
    c_list[i].next = &c_list[i + 1];
  }
  c_free_list_head = &c_list[0];
  for (i = 0; i < MAX_IOQUERY; i++) {
    c_list[i].tcp = -1;
  }
}

client *client_new(client **head)
{
  client *new;
  if (!c_free_list_head) return 0;

  /* remove query from front of free list */
  new = c_free_list_head;
  c_free_list_head = new->next;

  /* add it to front of nominated list*/
  new->next = *head;
  *head = new;

  return new;
}

void client_buf_free(client *x)
{
  if (!x->buf) return;
  alloc_free(x->buf);
  x->buf = 0;
  x->len = 0;
}

void client_free(client **head, client *x)
{
  client *t;
  client *p;

  t = *head;
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
    *head = x->next;
  }
  x->next = c_free_list_head;
  c_free_list_head = x;
  x->query_number = 0;
  x->loop = 0;
  x->udp_size = 0;
  x->tcp = -1;
  dns_domain_free(&x->name);
  /* dns_type_set(&x->type, DNS_T_NIL); */
  client_buf_free(x);
  query_free_list(&x->qlist);
}

client *client_find_oldest(client *head)
{
  client *x;
  client *y;

  x = y = head;
  while (x) {
    if (taia_less(&x->start, &y->start)) {
      y = x;
    }
    x = x->next;
  }
  return y;
}

void client_move(client *x, client **from, client **to)
{
  client *t;
  client *p;

  t = *from;
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
    *from = x->next;
  }
  x->next = *to;
  *to = x;
  x->io = 0;
}

void client_drop_active(client *x)
{
  switch (x->ctype) {
    case UDP_CLIENT:
      udpclient_drop_active(x);
      break;
    case TCP_CLIENT:
      tcpclient_drop_active(x);
      break;
    default:  /* catch bug */
      die_internal();
      break;
  }
}

void client_to_ioquery_list(client *x)
{
  switch (x->ctype) {
    case UDP_CLIENT:
      udpclient_to_ioquery_list(x);
      break;
    case TCP_CLIENT:
      tcpclient_to_ioquery_list(x);
      break;
    default:  /* catch bug */
      die_internal();
      break;
  }
}

void client_end_ioquery(client *x)
{
  switch (x->ctype) {
    case UDP_CLIENT:
      udpclient_end_ioquery(x);
      break;
    case TCP_CLIENT:
      tcpclient_end_ioquery(x);
      break;
    default:  /* catch bug */
      die_internal();
      break;
  }
}

/* cname prohibited in ns - RFC 2181 s10.3 */
/* cname prohibited in mx - RFC 2181 s10.3 */
unsigned int client_do_cname(const dns_type *type)
{
  if (dns_type_equal(dns_t_ns, type)) return 0;
/*
  disable this - too many nimrods using cnames in CDNs
  if (dns_type_equal(dns_t_mx, type)) return 0;
*/
  return 1;
}
