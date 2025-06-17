#include <nemo/socket.h>

#include "dns.h"
#include "response.h"

void response_send4(int fd, const ip4_address *ip, uint16_t port)
{
  socket4_send(fd, response, response_len, ip, port);
}
