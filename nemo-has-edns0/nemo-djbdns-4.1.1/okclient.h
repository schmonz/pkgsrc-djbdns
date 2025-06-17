#ifndef NEMO_OKCLIENT_H
#define NEMO_OKCLIENT_H

#include <nemo/stdint.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>

unsigned int okclient4(const ip4_address *ip);
unsigned int okclient6(const ip6_address *ip);

#endif
