#include "dns.h"

/*
  remove element 'pos' by shuffle down (preserves order),
  then shorten vector by 1
*/
unsigned int mxname_vector_remove(register mxname_vector *vector, register unsigned int pos)
{
  register unsigned int last;

  last = vector->len;
  if (!last) return 1;  /* zero length, nothing to do */
  last--;
  while (pos < last) {
    if (!stralloc_copy(&vector->va[pos].sa, &vector->va[pos + 1].sa)) return 0;
    vector->va[pos].pref = vector->va[pos + 1].pref;
    pos++;
  }
  stralloc_free(&vector->va[pos].sa);
  vector->len--;
  return 1;
}
