#ifndef UDPCLIENT4_H
#define UDPCLIENT4_H

void	udpclient_setup(void);
void	udpclient_setup_socket(const ip4_address *ip_incoming);
int	udpclient_socket(void);

void	udpclient_start(void);
void	udpclient_try(client *);

void	udpclient_drop_active(client *u);
void	udpclient_respond(client *u);
void	udpclient_to_ioquery_list(client *u);
void	udpclient_end_ioquery(client *x);

client	*udpclient_active_list_head(void);
client	*udpclient_dropping_list_head(void);

#endif /* UDPCLIENT4_H */
