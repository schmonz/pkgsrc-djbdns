#include <nemo/str.h>
#include <nemo/byte.h>
#include <nemo/scan.h>
#include <nemo/exit.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/error.h>
#include <nemo/ip4.h>

#include "dns.h"
#include "die.h"
#include "response.h"
#include "printpacket.h"
#include "respond.h"

const char USAGE[] = "type name [ip]";

static ip4_address ip = IP4_ADDRESS;
static dns_type type = DNS_TYPE;
static dns_domain name = DNS_DOMAIN;

static stralloc out = STRALLOC;

int main(int argc, char **argv)
{
  PROGRAM = *argv;
  if (argc < 3 || argc > 4) die_usage();

  ++argv;
  if (!dns_type_parse(&type, *argv)) die_parse("type", *argv);

  ++argv;
  if (!dns_domain_fromdot(&name, *argv, str_len(*argv))) {
    if (errno == error_nomem) die_nomem();
    if (errno == error_proto) die_parse("name", *argv);
    die_internal();
  }

  if (*++argv) {
    if (!ip4_scan(&ip, *argv)) die_parse("ip", *argv);
  }

  if (!stralloc_erase(&out)) die_nomem();
  if (!stralloc_catulong0(&out, dns_type_get(&type), 0)) die_nomem();
  if (!stralloc_append(&out, " ")) die_nomem();
  if (!dns_domain_todot_cat(&name, &out)) die_nomem();
  if (!stralloc_append(&out, ":")) die_nomem();
  if (!stralloc_append(&out, "\n")) die_nomem();

  if (!response_query(&name, &type, dns_c_in)) die_parse("packet", "data");
  response[3] &= (byte_t)(~128);
  response[2] &= (byte_t)(~1);
  response[2] |= 4;
  dns_domain_lower(&name);

  if (dns_type_equal(&type, dns_t_axfr)) {
    response_notimp();
  }
  else {
    if (!respond4(&name, &type, &ip, DNS_UDP_SIZE_MAX, 0)) goto DONE;
  }

  if (!printpacket_cat(response, response_len, &out)) die_parse("packet", "data");

DONE:
  djbio_putsaflush(djbiofd_out, &out);
  _exit(0);
}
