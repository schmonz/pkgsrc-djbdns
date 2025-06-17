#include <sys/types.h>
#include <sys/stat.h>

#include <nemo/str.h>

#include "okclient.h"

static char fn[3 + IP6_FMT] = "ip/";

unsigned int okclient6(const ip6_address *ip)
{
  struct stat st;
  unsigned int i;
/*
  fn[0] = 'i';
  fn[1] = 'p';
  fn[2] = '/';
*/
  fn[3 + ip6_fmt_uncompressed(ip, fn + 3)] = '\0';
  for (;;) {
    if (stat(fn, &st) == 0) return 1;
    /* treat temporary error as rejection */
    i = str_rchr(fn, ':');
    if (!fn[i]) return 0;
    fn[i] = '\0';
  }
}
