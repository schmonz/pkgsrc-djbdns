#include <nemo/byte.h>
#include <nemo/macro_unused.h>

#include "dns.h"
#include "dd.h"
#include "respond.h"
#include "response.h"

void initialize(void)
{
  ;
}

unsigned int respond6(const dns_domain *q, const dns_type *qtype, const ip6_address *ipu __UNUSED__, unsigned int udp_size __UNUSED__, unsigned int flag_edns0 __UNUSED__)
{
  unsigned int flag_aaaa;
  unsigned int flag_ptr;
  ip6_address ip;
  int j;

  flag_aaaa = dns_type_equal(qtype, dns_t_aaaa);
  flag_ptr = dns_type_equal(qtype, dns_t_ptr);
  if (dns_type_equal(qtype, dns_t_any)) {
    flag_aaaa = flag_ptr = 1;
  }

  if (flag_aaaa || flag_ptr) {
    if (dd6(q, dns_d_empty, &ip) == 32) {
      if (flag_aaaa) {
        if (!response_rr_start(q, dns_t_aaaa, 655360)) return 0;
        if (!response_addip6(&ip)) return 0;
        response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
      }
      return 1;
    }
    j = dd6(q, dns_d_base_ip6_arpa, &ip);
    if (j >= 0) {
      if (flag_aaaa && (j == 32)) {
        if (!response_rr_start(q, dns_t_aaaa, 655360)) return 0;
        if (!response_addip6_r(&ip)) return 0;
        response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
      }
      if (flag_ptr) {
        if (!response_rr_start(q, dns_t_ptr, 655360)) return 0;
        if (!response_addname(q)) return 0;
        response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
      }
      return 1;
    }
  }

  response[2] &= (byte_t)(~4);
  response_refused();
  return 3;  /* REJECTED */
}
