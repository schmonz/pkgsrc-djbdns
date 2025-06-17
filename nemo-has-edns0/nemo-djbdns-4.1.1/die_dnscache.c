#include "die.h"

void die_newquery(void)
{
  die1("query slots exhausted");
}

void die_newioquery(void)
{
  die1("ioquery slots exhausted");
}

void die_getioquery(void)
{
  die1("ioquery: dns_transmit_get() unexpected result");
}

void die_newtcpclient(void)
{
  die1("tcpclient slots exhausted");
}

void die_newudpclient(void)
{
  die1("udpclient slots exhausted");
}

void die_tcpsocket(void)
{
  die1("TCP socket error");
}

void die_udpsocket(void)
{
  die1("UDP socket error");
}
