#include "dns.h"
#include "tdlookup.h"
#include "respond.h"
#include "data_cdb.h"

unsigned int respond6(const dns_domain *qname, const dns_type *qtype, const ip6_address *ip, unsigned int udp_size, unsigned int flag_edns0)
{
  char key[KEY_PREFIX_LEN+16];

  data_cdb_setup();
  key[0] = '\0';
  key[1] = '%';
  key[2] = '6';
  key[3] = '\0';  /* padding */
  ip6_pack(ip, key + KEY_PREFIX_LEN);
  if (!tdlookup_loc_setup(key, sizeof key)) return 0;
  return tdlookup_doit(qname, qtype, udp_size, flag_edns0);
}
