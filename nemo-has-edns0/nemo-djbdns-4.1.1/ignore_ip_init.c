#include <nemo/stdint.h>
#include <nemo/ip4.h>
#include <nemo/ip6.h>
#include <nemo/stralloc.h>
#include <nemo/sa_vector.h>
#include <nemo/openreadclose.h>
#include <nemo/error.h>

#include "ignore_ip_init.h"
#include "die.h"

static const char FN_IGNORE_IP4[] = "ignoreip4";
static const char FN_IGNORE_IP6[] = "ignoreip6";

ip4_vector ignore_ip4_list = IP4_VECTOR;
ip6_vector ignore_ip6_list = IP6_VECTOR;

void ignore_ip4_init(void)
{
  sa_vector lines;
  stralloc *line;
  ip4_address ip;
  unsigned int i;

  sa_vector_init(&lines);
  if (openreadlistclose(FN_IGNORE_IP4, &lines) < 0) {
    sa_vector_free(&lines);
    if (errno == error_nomem) die_nomem();
    die_read(FN_IGNORE_IP4);
  }
  for (i = 0; i < lines.len; ++i) {
    line = &lines.va[i];
    if (!stralloc_0(line)) die_nomem();
    if (ip4_scan(&ip, line->s)) {
      if (!ip4_vector_append(&ignore_ip4_list, &ip)) die_nomem();
    }
  }
  sa_vector_free(&lines);
  ip4_vector_sort(&ignore_ip4_list);
}

void ignore_ip6_init(void)
{
  sa_vector lines;
  stralloc *line;
  ip6_address ip;
  unsigned int i;

  sa_vector_init(&lines);
  if (openreadlistclose(FN_IGNORE_IP6, &lines) < 0) {
    sa_vector_free(&lines);
    if (errno == error_nomem) die_nomem();
    die_read(FN_IGNORE_IP6);
  }
  for (i = 0; i < lines.len; ++i) {
    line = &lines.va[i];
    if (!stralloc_0(line)) die_nomem();
    if (ip6_scan(&ip, line->s)) {
      if (!ip6_vector_append(&ignore_ip6_list, &ip)) die_nomem();
    }
  }
  sa_vector_free(&lines);
  ip6_vector_sort(&ignore_ip6_list);
}
