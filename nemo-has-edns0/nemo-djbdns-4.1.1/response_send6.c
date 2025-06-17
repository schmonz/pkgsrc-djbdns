#include <nemo/socket.h>

#include "dns.h"
#include "response.h"

void response_send6(int fd, const ip6_address *ip, uint16_t port)
{
  socket6_send(fd, response, response_len, ip, port);
}
