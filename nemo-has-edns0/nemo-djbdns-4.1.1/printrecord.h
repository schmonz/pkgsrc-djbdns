#ifndef NEMO_PRINTRECORD_H
#define NEMO_PRINTRECORD_H

#include <nemo/stralloc.h>

unsigned int printrecord_cat(const byte_t *buf, unsigned int len, unsigned int pos, const dns_domain *q, const dns_type *qtype, stralloc *out);
unsigned int printrecord(const byte_t *buf, unsigned int len, unsigned int pos, const dns_domain *q, const dns_type *qtype, stralloc *out);

#endif
