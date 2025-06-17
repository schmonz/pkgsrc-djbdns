#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/env.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "wildlookup.h"
#include "respond.h"
#include "data_cdb.h"

unsigned int respond4(const dns_domain *qname, const dns_type *qtype, const ip4_address *ip __UNUSED__, unsigned int udp_size __UNUSED__, unsigned int flag_edns0 __UNUSED__)
{
  data_cdb_setup();
  return wildlookup_doit(qname, qtype);
}
