#ifndef TCPCLIENT6_H
#define TCPCLIENT6_H

void	tcpclient_setup(void);
void	tcpclient_setup_socket(const ip6_address *ip_incoming);
int	tcpclient_socket(void);

void	tcpclient_start(void);
void	tcpclient_try(client *t);

unsigned int tcpclient_ioready(const client *x, const struct taia *stamp);

void	tcpclient_do_datasize(client *t);
void	tcpclient_do_payload(client *t);
void	tcpclient_do_query(client *t);
void	tcpclient_do_response(client *t);
void	tcpclient_drop_active(client *t);
void	tcpclient_to_ioquery_list(client *t);
void	tcpclient_end_ioquery(client *x);

client	*tcpclient_datasize_list_head(void);
client	*tcpclient_payload_list_head(void);
client	*tcpclient_active_list_head(void);
client	*tcpclient_response_list_head(void);
client	*tcpclient_dropping_list_head(void);

#endif /* TCPCLIENT6_H */
