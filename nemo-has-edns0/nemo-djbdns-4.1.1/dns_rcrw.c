#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/stralloc.h>
#include <nemo/sa_vector.h>
#include <nemo/env.h>
#include <nemo/openreadclose.h>
#include <nemo/str.h>
#include <nemo/ip4.h>
#include <nemo/unix.h>

#include "dns.h"
#include "whitespace.h"

static sa_vector lines = SA_VECTOR;
static sa_vector domains = SA_VECTOR;
static stralloc tmp = STRALLOC;

static int init(sa_vector *rules)
{
  stralloc *data;
  char host[256];
  const char *x;
  unsigned int i;
  unsigned int j;

  if (!sa_vector_erase(rules)) return -1;

  if (!sa_vector_appends(rules, "=localhost:127.0.0.1")) return -1;

  x = env_get("DNSREWRITEFILE");
  if (!x) {
    x = "/etc/dnsrewrite";
  }

  if (openreadlistclose(x, &lines) < 0) return -1;
  if (lines.len) {
    for (j = 0; j < lines.len; ++j) {
      if (!sa_vector_append(rules, &lines.va[j])) return -1;
    }
    return 0;
  }

  x = env_get("LOCALDOMAIN");
  if (x) {
    if (!stralloc_copys(&tmp, x)) return -1;
    stralloc_trim(&tmp, DNS_WHITESPACE, DNS_WHITESPACE_LEN);
    if (!sa_vector_parse(&domains, &tmp, " \t", 2)) return -1;
    if (!stralloc_copys(&tmp, "?:")) return -1;
    for (j = 0; j < domains.len; ++j) {
      if (domains.va[j].len) {
	if (!stralloc_cats(&tmp, "+.")) return -1;
	if (!stralloc_cat(&tmp, &domains.va[j])) return -1;
      }
    }
    if (tmp.len > 2) {
      if (!sa_vector_append(rules, &tmp)) return -1;
      if (!sa_vector_appends(rules, "*.:")) return -1;
      return 0;
    }
  }

  if (openreadlistclose("/etc/resolv.conf", &lines) < 0) return -1;
  for (j = 0; j < lines.len; ++j) {
    data = &lines.va[j];
    if (stralloc_starts(data, "search") || stralloc_starts(data, "domain")) {
      i = 7;
      for (;;) {
	if (i >= data->len) break;
	if ((data->s[i] != ' ') && (data->s[i] != '\t')) break;
	++i;
      }
      if (!stralloc_copyb(&tmp, data->s + i, data->len - i)) return -1;
      if (!sa_vector_parse(&domains, &tmp, " \t", 2)) return -1;
      if (!stralloc_copys(&tmp, "?:")) return -1;
      for (j = 0; j < domains.len; ++j) {
	if (domains.va[j].len) {
	  if (!stralloc_cats(&tmp, "+.")) return -1;
	  if (!stralloc_cat(&tmp, &domains.va[j])) return -1;
	}
      }
      if (tmp.len > 2) {
	if (!sa_vector_append(rules, &tmp)) return -1;
	if (!sa_vector_appends(rules, "*.:")) return -1;
	return 0;
      }
    }
  }

  host[0] = 0;
  if (gethostname(host, sizeof(host)) < 0) return -1;
  host[sizeof(host) - 1] = 0;
  i = str_chr(host, '.');
  if (host[i]) {
    if (!stralloc_copys(&tmp, "?:")) return -1;
    if (!stralloc_cats(&tmp, host + i)) return -1;
    if (!sa_vector_append(rules, &tmp)) return -1;
  }
  if (!sa_vector_appends(rules, "*.:")) return -1;

  return 0;
}

static unsigned int ok = 0;
static unsigned int uses;
static struct taia deadline;
static sa_vector rules = SA_VECTOR; /* defined if ok */

int dns_resolve_conf_rewrite(sa_vector *out)
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
    if (init(&rules) < 0) return -1;
    taia_uint(&deadline, 600);
    taia_add(&deadline, &now, &deadline);
    uses = 10000;
    ok = 1;
  }

  --uses;
  if (!sa_vector_copy(out, &rules)) return -1;
  return 0;
}
