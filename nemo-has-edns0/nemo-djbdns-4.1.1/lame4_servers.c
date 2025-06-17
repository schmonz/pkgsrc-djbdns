#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/unix.h>

#include "dns.h"
#include "die.h"

#include "lame4_servers.h"

static lame4_vector lame_servers = LAME4_VECTOR;

unsigned int lame4_servers_count(void)
{
  return lame4_vector_len(&lame_servers);
}

void lame4_servers_add(const dns_domain *control, const ip4_address *server, uint32_t ttl)
{
  static lame4_data data = LAME4_DATA;
  lame4_data *cur;
  lame4_data *end;
  time_t now;

  if (ttl < LAME_TTL) {  /* RFC4697 s2.2.1 */
    ttl = LAME_TTL;
  }
  now = unix_now();
  lame4_vector_purge(&lame_servers, now);
/*
  search for existing entry, if exists overwrite expire
*/
  cur = lame_servers.va;
  end = cur + lame_servers.len;
  while (cur < end) {
    if (dns_domain_equal(&cur->control, control)) {
      if (ip4_equal(&cur->ip, server)) {
        cur->expire = now + (time_t)ttl;
        return;
      }
    }
    cur++;
  }
/*
  create new entry (append)
*/
  if (!dns_domain_copy(&data.control, control)) die_nomem();
  ip4_copy(&data.ip, server);
  data.expire = now + (time_t)ttl;
  if (!lame4_vector_append(&lame_servers, &data)) die_nomem();
}

void lame4_servers_prune(const dns_domain *control, ip4_vector *servers)
{
  lame4_data *cur;
  lame4_data *end;
  time_t now;
  register unsigned int j;

  now = unix_now();
  ip4_vector_sort(servers);
  cur = lame_servers.va;
  end = cur + lame_servers.len;
  while (cur < end) {
    if (cur->expire > now) {
      if (dns_domain_equal(&cur->control, control)) {
	j = ip4_vector_find(servers, &cur->ip);
	if (j != servers->len) {
	  ip4_vector_remove(servers, j, 1);
	}
      }
    }
    cur++;
  }
}
