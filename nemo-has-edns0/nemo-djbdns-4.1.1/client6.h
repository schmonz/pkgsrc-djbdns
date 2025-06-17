#ifndef CLIENT6_H
#define CLIENT6_H

#include "cache.h"
#include "client.h"
#include "query.h"

typedef struct _client {
  client_type_t ctype;		/* client type: 0 = udp, 1 = tcp */
  unsigned int loop;		/* keep track of interations */
  uint64_t query_number;	/* if active >0; otherwise 0 */
  unsigned int flag_edns0;	/* allow for larger udp packets */
  unsigned int udp_size;	/* UDP packet size */
  ip6_address ip;		/* send response to this address */
  uint16_t port;		/* send response to this port */
  dns_id id;			/* query id from client */
  dns_domain name;		/* query name */
  dns_type type;		/* query type */
  dns_class class;		/* query class */
  struct taia start;		/* query start */
  struct taia timeout;		/* tcp timeout value */
  iopause_fd *io;		/* */
  int tcp;			/* open TCP socket, if active */
  byte_t *buf;			/* 0, or dynamically allocated of length len */
  unsigned int len;		/* buf length */
  unsigned int pos;		/* pos if current data ptr */
  client_ptr next;		/* next client in list */
  query_ptr qlist;		/* additional query list */
} client;

void	client_setup(void);
void	client_buf_free(client *x);
void	client_free(client **head, client *x);

query_cache_t	client_answer(client *x);

client	*client_new(client **head);
client	*client_find_oldest(client *head);

void	client_move(client *x, client **from, client **to);
void	client_to_ioquery_list(client *x);
void	client_drop_active(client *x);
void	client_end_ioquery(client *x);

unsigned int	client_do_cname(const dns_type *type);

#endif /* CLIENT6_H */
