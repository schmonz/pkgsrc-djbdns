#include "dns.h"

/*
  domain data format...
    byte(len1), byte_array[len1], byte(len2), byte_array[len2], ... '\0'
*/

unsigned int byte_domain_length(const void *dn)
{
  register const byte_t *x;
  register const byte_t *orig;
  register byte_t c;

  orig = x = dn;
  while ((c = *x++)) {
    x += (unsigned int)c;
  }
  return (unsigned int)(x - orig);
}
