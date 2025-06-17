/* Public domain. */

#include "dns.h"

#define X(v,s) if (i == (v)) return (s);

const char *dns_type_str(unsigned int i)
{
  X(DNS_T_NIL, "nil")
  X(DNS_T_A, "a")
  X(DNS_T_NS, "ns")
  X(DNS_T_CNAME, "cname")
  X(DNS_T_SOA, "soa")
  X(DNS_T_PTR, "ptr")
  X(DNS_T_HINFO, "hinfo")
  X(DNS_T_MX, "mx")
  X(DNS_T_TXT, "txt")
  X(DNS_T_RP, "rp")
  X(DNS_T_SIG, "sig")
  X(DNS_T_KEY, "key")
  X(DNS_T_AAAA, "aaaa")
  X(DNS_T_LOC, "loc")
  X(DNS_T_SRV, "srv")
  X(DNS_T_NAPTR, "naptr")
  X(DNS_T_OPT, "opt")
  X(DNS_T_DS, "ds")
  X(DNS_T_RRSIG, "rrsig")
  X(DNS_T_NSEC, "nsec")
  X(DNS_T_DNSKEY, "dnskey")
  X(DNS_T_SPF, "spf")
  X(DNS_T_IXFR, "ixfr")
  X(DNS_T_AXFR, "axfr")
  X(DNS_T_ANY, "any")
  X(DNS_T_CAA, "caa")
  return 0;
}
