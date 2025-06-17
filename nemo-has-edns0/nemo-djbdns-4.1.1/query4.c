#include <nemo/error.h>
#include <nemo/byte.h>
#include <nemo/fmt.h>

#include "dnscache.h"
#include "log.h"
#include "roots.h"
#include "dd.h"
#include "response.h"
#include "dn_vector.h"
#include "cache.h"
#include "die.h"
#include "lame4_servers.h"

#include "client4.h"
#include "ioquery4.h"
#include "query4.h"
#include "tcpclient4.h"
#include "udpclient4.h"

/* #define DEBUG 1 */
#include "debug.h"

static query q_list[MAX_QUERY];

static query *q_free_list_head = 0;

static unsigned int flag_forwardonly = 0;

static void free_servers(query *z)
{
  ip4_vector_free(&z->servers);
}


#include "query.c"


static void mark_host_glueless(const dns_domain *control, const dns_domain *name)
{
  log_glueless_a(name, control);
  cache_mark(dns_t_a, name, CACHE_NXDOMAIN, 0);
}

static unsigned int do_query_servers(query *z)
{
  dns_sortip4(&z->servers);
  if (ioquery_start(z, &z->servers, flag_forwardonly, (z->client->ctype) ? 0 : edns0_enabled, &z->name, &z->type, &z->control)) return 1;
  return 0;
}

/* search query chain for ns loop */
static unsigned int ns_loop_exists(query *z, dns_domain *name)
{
  register query *t;
  t = z->next;
  while (t) {
    if (dns_domain_equal(name, &t->name) && dns_type_equal(dns_t_a, &t->type)) return 1;
    t = t->next;
  }
  return 0;
}

/*****************************************************************************/

/*
  look for all NS with A record

  R_QUERY_NS_ROOTS: roots first
  R_QUERY_NS_IP_FOUND: 1 or more entries,
  R_QUERY_NS_NEWQUERY: query dispatched,
  R_QUERY_NS_FAIL: error
*/
static query_ns_t do_query_ns(query *z)
{
  static ip4_vector servers = IP4_VECTOR;
  register dns_domain *qname;
  register dns_domain *qcontrol;
  register cache_t status;
  unsigned int i;
  unsigned int ns_errors;

  if (!z->ns.len) return R_QUERY_NS_ROOTS;

  ns_errors = 0;
  qcontrol = &z->control;
  debug_putuint("do_query_ns:z->ns.len", z->ns.len);
  for (i = 0; i < z->ns.len; i++) {
    qname = &z->ns.va[i];
    debug_putdomain("do_query_ns:qname", qname);
    if (cache_test_rr(dns_t_cname, qname) == CACHE_HIT) {  /* cname prohibited in ns - RFC 2181 s10.3 */
      log_ns_cname(&z->name, qname);
      cache_mark(dns_t_a, qname, CACHE_SERVFAIL, 0);
      ns_errors++;
      continue;
    }
    if (ns_loop_exists(z, qname)) {
      log_ns_loop(&z->name, qname);
      cache_mark(dns_t_a, qname, CACHE_SERVFAIL, 0);
      ns_errors++;
      continue;
    }
    status = cache_get_rr_a(qname, &servers);
    debug_putuint("do_query_ns:cache_get_rr_a", status);
    if (status == CACHE_HIT) {
      if (!ip4_vector_cat(&z->servers, &servers)) die_nomem();
      debug_putuint("do_query_ns:servers.len", servers.len);
      continue;
    }
    if (status == CACHE_MISS) {
      if (dns_domain_suffix(qname, qcontrol)) {  /* subdomain, missing glue */
        mark_host_glueless(qcontrol, qname);
        ns_errors++;
        continue;
      }
      query_start(z->client, dns_t_a, qname, 0);
      debug_putquery("do_query_ns:query_start", qname, dns_t_a);
      return R_QUERY_NS_NEWQUERY;
    }
    if (status == CACHE_EXPIRED) {
      if (dns_domain_suffix(qname, qcontrol)) {  /* subdomain, its all about the glue */
        debug_putuint("do_query_ns:z->retry_glueless", z->retry_glueless);
        if (z->retry_glueless++) {  /* second time */
          mark_host_glueless(qcontrol, qname);
          return R_QUERY_NS_RETRY;
        }
        /* if glue expires before NS, invalidate NS+host, retry once */
        cache_mark(dns_t_ns, qcontrol, CACHE_MISS, 0);
      }
      cache_mark(dns_t_a, qname, CACHE_MISS, 0);
      return R_QUERY_NS_RETRY;
    }
    /* CACHE_NXDOMAIN, CACHE_SERVFAIL */
    ns_errors++;
  }

  debug_putuint("do_query_ns:ns_errors", ns_errors);
  if (ns_errors == z->ns.len) {
    log_ns_fail(&z->name, qcontrol);
    /* cache_mark(dns_t_ns, qcontrol, CACHE_SERVFAIL, 0); */
    return R_QUERY_NS_FAIL;
  }

  lame4_servers_prune(qcontrol, &z->servers);

  debug_putuint("do_query_ns:z->servers.len", z->servers.len);
  if (z->servers.len) {  /* IPs found */
    free_ns(z);
    return R_QUERY_NS_IP_FOUND;
  }

  log_ns_fail(&z->name, qcontrol);
  /* cache_mark(dns_t_ns, qcontrol, CACHE_SERVFAIL, 0); */
  return R_QUERY_NS_FAIL;
}

/* 0: config error, 1: OK */
static unsigned int get_roots_or_ns(register query *z)
{
  register unsigned int len;
  dns_domain dn;

  dn = z->name;
  for (;;) {
    debug_putdomain("get_roots_or_ns:dn", &dn);
    if (roots4(&dn, &z->servers)) break;
    if (!flag_forwardonly) {
      if (cache_get_rr_ns(&dn, &z->ns) == CACHE_HIT) break;
    }
    len = dn.data[0];
    if (!len) return 0;  /* config error */
    len++;  /* include 'label length' byte */
    dn.data += len;  /* simulate drop label, pt 1 */
    dn.len -= len;  /* simulate drop label, pt 2 */
  }
  if (!dns_domain_copy(&z->control, &dn)) die_nomem();
  return 1;
}

query_event_t query_try(register query *z)
{
  register query_ns_t r;

  free_servers(z);
  free_ns(z);

  if (!get_roots_or_ns(z)) {
    log_local_fail(&z->name, &z->type, "roots config error");
    return R_QUERY_EVENT_FAIL;
  }

  r = do_query_ns(z);
  if (r == R_QUERY_NS_FAIL) return R_QUERY_EVENT_FAIL;
  if (r == R_QUERY_NS_NEWQUERY) return R_QUERY_EVENT_NEW;  /* new query dispatched */
  if (r == R_QUERY_NS_RETRY) return R_QUERY_EVENT_RETRY;  /* new query dispatched */

  /* R_QUERY_NS_IP_FOUND or R_QUERY_NS_ROOTS */
  if (do_query_servers(z)) {
    move_to_ioquery_list(z);
    return R_QUERY_EVENT_IOQUERY;  /* new ioquery dispatched */
  }

  log_local_fail(&z->name, &z->type, "servers unreachable");
  return R_QUERY_EVENT_FAIL;
}
