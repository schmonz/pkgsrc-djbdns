#include <nemo/error.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/sgetopt.h>
#include <nemo/exit.h>
#include <nemo/str.h>
#include <nemo/char.h>

#include "dns.h"
#include "die.h"

const char USAGE[] = "[ -1qQt ] -s rblservice ip";

static unsigned int flag_exit_on_first = 0;
static unsigned int flag_quiet = 0;
static unsigned int flag_rr_txt = 0;

static void output_text_results(const stralloc *server, const stralloc *result)
{
  if (flag_quiet) return;
  djbio_putsa(djbiofd_out, server);
  djbio_put(djbiofd_out, ": ", 2);
  djbio_putsa(djbiofd_out, result);
  djbio_puteol(djbiofd_out);
  djbio_flush(djbiofd_out);
}

static void output_ip_results(const stralloc *server, const ip4_address *result)
{
  char result_ipstr[IP4_FMT];
  unsigned int result_ipstr_len;
  if (flag_quiet) return;
  result_ipstr_len = ip4_fmt(result, result_ipstr);
  djbio_putsa(djbiofd_out, server);
  djbio_put(djbiofd_out, ": ", 2);
  djbio_put(djbiofd_out, result_ipstr, result_ipstr_len);
  djbio_puteol(djbiofd_out);
  djbio_flush(djbiofd_out);
}

static stralloc ip_reverse = STRALLOC;
static stralloc fqdn = STRALLOC;
static sa_vector text_results = SA_VECTOR;
static ip4_vector ip_results = IP4_VECTOR;

static dns_domain d = DNS_DOMAIN;
static sa_vector base_list = SA_VECTOR;

static unsigned int count = 0;

static void fmt_ip4_reverse(const ip4_address *ip)
{
  char ipstr[IP4_FMT];
  ip4_address reverse_ip;

  ip4_copy(&reverse_ip, ip);
  ip4_reverse(&reverse_ip);
  if (!stralloc_copyb(&ip_reverse, ipstr, ip4_fmt(&reverse_ip, ipstr))) die_nomem();
  if (!stralloc_append(&ip_reverse, ".")) die_nomem();
}

static void check_rbls(void)
{
  unsigned int i;
  stralloc *current_server;
  for (i = 0; i < base_list.len; i++) {
    current_server = &base_list.va[i];
    if (!stralloc_copy(&fqdn, &ip_reverse)) die_nomem();
    if (!stralloc_cat(&fqdn, current_server)) die_nomem();
/*
    djbio_putsa(djbiofd_out, &fqdn);
    djbio_puteol(djbiofd_out);
    djbio_flush(djbiofd_out);
*/
    if (flag_rr_txt) {
      if (dns4_txt(&text_results, &fqdn) < 0) die_dns_query();
      if (text_results.len) {
        count++;
        if (flag_exit_on_first) return;
        output_text_results(current_server, &text_results.va[0]);
      }
    }
    else {
      if (dns4_ip4(&ip_results, &fqdn) < 0) die_dns_query();
      if (ip_results.len) {
        count++;
        if (flag_exit_on_first) return;
        output_ip_results(current_server, &ip_results.va[0]);
      }
    }
  }
}

int main(int argc, char **argv)
{
  char seed[128];
  ip4_address ip4;
  ip6_address ip6;
  unsigned int i;
  char *x;
  int opt;

  PROGRAM = *argv;
  dns_random_init(seed);

  while ((opt = getopt(argc, argv, "1qQs:t")) != opteof) {
    switch (opt) {
      case '1':
        flag_exit_on_first = 1;
        break;
      case 'q':
        flag_quiet = 1;
        break;
      case 'Q':
        flag_quiet = 0;
        break;
      case 's':
	if (!dns_domain_fromdot(&d, optarg, str_len(optarg))) {
	  if (errno == error_nomem) die_nomem();
	  if (errno == error_proto) die_parse("rblservice", optarg);
	  die_internal();
	}
        if (!sa_vector_appends(&base_list, optarg)) die_nomem();
        break;
      case 't':
        flag_rr_txt = 1;
        break;
      default:
        die_usage();
        break;
    }
  }
  argv += optind;

  if (!base_list.len) die_usage1("RBL service not defined");

  x = *argv;
  if (!x || !*x) die_usage1("IP address not supplied");

  i = ip4_scan(&ip4, x);
  if (!i || x[i]) {
    i = ip6_scan(&ip6, x);  /* if IPv6 - will not be found in IPv4 RBL */
    if (!x[i]) _exit(0);
    die_parse("IPv4 address", x);
  }
  fmt_ip4_reverse(&ip4);
  check_rbls();
  _exit((count) ? 1 : 0);
}
