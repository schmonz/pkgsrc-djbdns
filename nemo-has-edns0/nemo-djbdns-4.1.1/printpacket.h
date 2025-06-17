#ifndef NEMO_PRINTPACKET_H
#define NEMO_PRINTPACKET_H

#include <nemo/stdint.h>
#include <nemo/stralloc.h>

unsigned int printpacket_cat(const byte_t *d, unsigned int len, stralloc *out);

#endif
