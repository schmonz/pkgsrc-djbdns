#include <nemo/stralloc.h>
#include <nemo/sa_vector.h>
#include <nemo/env.h>
#include <nemo/openreadclose.h>
#include <nemo/error.h>

#include "dns.h"

#define DNS_MAX_NAME_SERVERS 16

static int init(ip4_vector *servers)
{
  static sa_vector lines = SA_VECTOR;

  stralloc *data;
  unsigned int i;
  unsigned int j;
  ip4_address ip;
  const char *x;

  if (!ip4_vector_erase(servers)) return -1;

  x = env_get("DNSCACHEIP");
  if (x) {
    while (servers->len < DNS_MAX_NAME_SERVERS) {
      if (*x == ' ' || *x == '\t' || *x == '\n') {
        ++x;
      }
      else {
        i = ip4_scan(&ip, x);
        if (!i) break;
        if (!ip4_vector_append(servers, &ip)) return -1;
        x += i;
      }
    }
  }

  if (!servers->len) {
    if (openreadlistclose("/etc/resolv.conf", &lines) < 0) return -1;
    if (!sa_vector_0(&lines)) return -1;
    for (j = 0; j < lines.len; ++j) {
      data = &lines.va[j];
      if (stralloc_starts(data, "nameserver")) {
	x = &data->s[10];
	while (*x) {
	  if ((*x != ' ') && (*x != '\t')) break;
	  x++;
	}
	if (!*x) continue;
	i = ip4_scan(&ip, x);
	if (!x[i]) {
	  if (servers->len < DNS_MAX_NAME_SERVERS) {
	    if (!ip4_vector_append(servers, &ip)) return -1;
	  }
	}
      }
    }
  }

  if (!servers->len) {
    if (!ip4_vector_append(servers, localhost_ip4)) return -1;
  }
  return 0;
}

static unsigned int ok = 0;
static unsigned int uses = 0;
static struct taia deadline = TAIA;
static ip4_vector servers = IP4_VECTOR; /* defined if ok */

int dns_resolve_conf_ip4(ip4_vector *s)
{
  struct taia now;

  taia_now(&now);
  if (taia_less(&deadline, &now)) {
    ok = 0;
  }
  if (!uses) {
    ok = 0;
  }

  if (!ok) {
    if (init(&servers) < 0) return -1;
    taia_uint(&deadline, 600);
    taia_add(&deadline, &now, &deadline);
    uses = 10000;
    ok = 1;
  }

  --uses;
  if (!ip4_vector_copy(s, &servers)) return -1;

  return 0;
}
