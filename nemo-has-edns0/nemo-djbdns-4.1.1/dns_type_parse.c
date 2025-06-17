#include <nemo/scan.h>
#include <nemo/byte.h>
#include <nemo/str.h>

#include "dns.h"

unsigned int dns_type_parse(dns_type *type, const char *s)
{
  unsigned long u;

  if (!s[scan_ulong(s, &u)]) type->d = (uint16_t)u;
  else if (str_case_equal(s, "a")) type->d = DNS_T_A;
  else if (str_case_equal(s, "ns")) type->d = DNS_T_NS;
  else if (str_case_equal(s, "cname")) type->d = DNS_T_CNAME;
  else if (str_case_equal(s, "soa")) type->d = DNS_T_SOA;
  else if (str_case_equal(s, "ptr")) type->d = DNS_T_PTR;
  else if (str_case_equal(s, "mx")) type->d = DNS_T_MX;
  else if (str_case_equal(s, "hinfo")) type->d = DNS_T_HINFO;
  else if (str_case_equal(s, "txt")) type->d = DNS_T_TXT;
  else if (str_case_equal(s, "rp")) type->d = DNS_T_RP;
  else if (str_case_equal(s, "sig")) type->d = DNS_T_SIG;
  else if (str_case_equal(s, "key")) type->d = DNS_T_KEY;
  else if (str_case_equal(s, "aaaa")) type->d = DNS_T_AAAA;
  else if (str_case_equal(s, "loc")) type->d = DNS_T_LOC;
  else if (str_case_equal(s, "srv")) type->d = DNS_T_SRV;
  else if (str_case_equal(s, "naptr")) type->d = DNS_T_NAPTR;
  else if (str_case_equal(s, "opt")) type->d = DNS_T_OPT;
  else if (str_case_equal(s, "ds")) type->d = DNS_T_DS;
  else if (str_case_equal(s, "rrsig")) type->d = DNS_T_RRSIG;
  else if (str_case_equal(s, "nsec")) type->d = DNS_T_NSEC;
  else if (str_case_equal(s, "dnskey")) type->d = DNS_T_DNSKEY;
  else if (str_case_equal(s, "spf")) type->d = DNS_T_SPF;
  else if (str_case_equal(s, "ixfr")) type->d = DNS_T_IXFR;
  else if (str_case_equal(s, "axfr")) type->d = DNS_T_AXFR;
  else if (str_case_equal(s, "any")) type->d = DNS_T_ANY;
  else if (str_case_equal(s, "caa")) type->d = DNS_T_CAA;
  else {
    return 0;
  }

  return 1;
}
