#ifndef NEMO_QUERY4_H
#define NEMO_QUERY4_H

#include <nemo/uint32.h>
#include <nemo/ip4.h>
#include <nemo/iopause.h>

#include "cache.h"
#include "query.h"

#define MAX_QUERY (QUERY_MAXLEVEL*MAX_IOQUERY)

typedef struct _query {
  dns_domain name;
  dns_type type;
  dns_class class;
  dns_domain control;
  unsigned int resolve_cname;
  unsigned int retry_glueless;
  dn_vector ns;
  ip4_vector servers;
  ioquery_ptr ioq;
  client_ptr client;
  query_ptr next;
} query;

void		query_forwardonly(void);
void		query_setup(void);
void		query_free_list(query **head);
void		query_end(query *z);
void		query_drop(query *z);
void		query_start(client_ptr x, const dns_type *type, const dns_domain *name, unsigned int do_cname);
query_event_t	query_try(query *z);

#endif
