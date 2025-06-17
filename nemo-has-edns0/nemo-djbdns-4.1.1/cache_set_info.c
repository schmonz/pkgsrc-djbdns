#include <nemo/byte.h>

#include "cache.h"
#include "log.h"

void cache_set_info(const char *what, const dns_type *type, const dns_domain *name, unsigned int status, unsigned int datalen)
{
  register const char *x;
  switch (status) {
    case CACHE_SET_NEW:
      x = "";
      break;
    case CACHE_SET_OVERWRITE:
      x = "-overwrite";
      break;
    case CACHE_SET_NOTFOUND:
      x = "-notfound";
      break;
    case CACHE_SET_NOTEXPIRED:
      x = "-notexpired";
      break;
    case CACHE_SET_HASHFLOOD:
      x = "-hashflood";
      break;
    case CACHE_SET_NOTALLOC:
      x = "-notalloced";
      break;
    case CACHE_SET_KEYLEN:
      x = "-keylenfail";
      break;
    case CACHE_SET_DATALEN:
      x = "-datalenfail";
      break;
    case CACHE_SET_EXHAUSTED:
      x = "-exhausted";
      break;
    default: x = "-fail";
    break;
  }
  log_cacheset(what, x, name, type, datalen);
}
