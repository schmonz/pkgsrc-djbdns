#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/error.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/sgetopt.h>
#include <nemo/exit.h>
#include <nemo/str.h>
#include <nemo/char.h>
#include <nemo/byte.h>
#include <nemo/strerr.h>

#include "dns.h"
#include "die.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>

const char USAGE[] = "[ -d ][ -46 ] domain";

static unsigned int flag_debug = 0;
static unsigned int flag_try_ip6_first = 0;
static unsigned int flag_notify_soa = 0;

static stralloc tmp = STRALLOC;
static stralloc domain = STRALLOC;
static const char *fqdn;

static ip4_vector local_ip4_list = IP4_VECTOR;
static ip6_vector local_ip6_list = IP6_VECTOR;

static sa_vector soa_name_list = SA_VECTOR;
static ip4_vector soa_ip4_list = IP4_VECTOR;
static ip6_vector soa_ip6_list = IP6_VECTOR;

static sa_vector ns_name_list = SA_VECTOR;
static ip4_vector ns_ip4_list = IP4_VECTOR;
static ip6_vector ns_ip6_list = IP6_VECTOR;

static ip4_vector ip4_list = IP4_VECTOR;
static ip6_vector ip6_list = IP6_VECTOR;

static char fmtstr[IP6_FMT];

static void print_name_list(const sa_vector *list, const char *caption)
{
  register unsigned int i;
  for (i = 0; i < list->len; i++) {
    djbio_putsa(djbiofd_out, &list->va[i]);
    djbio_put(djbiofd_out, " ", 1);
    djbio_puts(djbiofd_out, caption);
    djbio_puteol(djbiofd_out);
  }
  djbio_flush(djbiofd_out);
}

static void print_ip4(const ip4_address *ip, const char *caption)
{
  fmtstr[ip4_fmt(ip, fmtstr)] = '\0';
  djbio_puts(djbiofd_out, fmtstr);
  djbio_put(djbiofd_out, " ", 1);
  djbio_puts(djbiofd_out, caption);
  djbio_puteol(djbiofd_out);
  djbio_flush(djbiofd_out);
}

static void print_ip4_list(const ip4_vector *list, const char *caption)
{
  register unsigned int i;
  for (i = 0; i < list->len; i++) {
    print_ip4(&list->va[i], caption);
  }
}

static void print_ip6(const ip6_address *ip, const char *caption)
{
  fmtstr[ip6_fmt(ip, fmtstr)] = '\0';
  djbio_puts(djbiofd_out, fmtstr);
  djbio_put(djbiofd_out, " ", 1);
  djbio_puts(djbiofd_out, caption);
  djbio_puteol(djbiofd_out);
  djbio_flush(djbiofd_out);
}

static void print_ip6_list(const ip6_vector *list, const char *caption)
{
  register unsigned int i;
  for (i = 0; i < list->len; i++) {
    print_ip6(&list->va[i], caption);
  }
}

static void get_local_ip_list(void)
{
  struct ifaddrs *ifaddr;
  struct ifaddrs *ifa;
  /* char *name; */
  int family;
  ip4_address ip4;
  ip6_address ip6;

  if (getifaddrs(&ifaddr) < 0) die_sys("network interfaces query failed");
  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    /* name = ifa->ifa_name; */
    if (!ifa->ifa_addr) continue;
    family = ifa->ifa_addr->sa_family;
    if (family == AF_INET) {
      ip4_unpack(&ip4, ifa->ifa_addr->sa_data);
      if (!ip4_vector_append(&local_ip4_list, &ip4)) die_nomem();
      /* fmtstr[ip4_fmt(&ip4, fmtstr)] = '\0'; */
    }
    else if (family == AF_INET6) {
      ip6_unpack(&ip6, ifa->ifa_addr->sa_data);
      if (!ip6_vector_append(&local_ip6_list, &ip6)) die_nomem();
      /* fmtstr[ip6_fmt(&ip6, fmtstr)] = '\0'; */
    }
/*
    else {
      fmtstr[0] = '\0';
    }
    if (fmtstr[0]) {
      strerr_warn4x("interface: ", name, " ", fmtstr);
    }
*/
  }
  freeifaddrs(ifaddr);
  ip4_vector_sort(&local_ip4_list);
  ip6_vector_sort(&local_ip6_list);
}

static void get_soa_name_list(void)
{
  static soa_vector soa_list = SOA_VECTOR;
  register unsigned int i;
  if (flag_try_ip6_first) {
    if (dns6_soa(&soa_list, &domain) < 0) die_dns_query1("SOA (IPv6)");
    if (!soa_name_list.len) {
      if (dns4_soa(&soa_list, &domain) < 0) die_dns_query1("SOA (IPv4)");
    }
  }
  else {
    if (dns4_soa(&soa_list, &domain) < 0) die_dns_query1("SOA (IPv4)");
    if (!soa_name_list.len) {
      if (dns6_soa(&soa_list, &domain) < 0) die_dns_query1("SOA (IPv6)");
    }
  }
  for (i = 0; i < soa_list.len; i++) {
    if (!sa_vector_append(&soa_name_list, &soa_list.va[i].mname)) die_nomem();
  }
  if (!soa_name_list.len) die_rr_query("SOA", fqdn);
  sa_vector_lower(&soa_name_list);
  sa_vector_sort(&soa_name_list);
  print_name_list(&soa_name_list, "SOA");
}

static void get_soa_ip_list(void)
{
  register unsigned int i;
  register unsigned int j;
  ip4_address *ip4;
  ip6_address *ip6;

  for (i = 0; i < soa_name_list.len; i++) {
    if (!stralloc_copy(&tmp, &soa_name_list.va[i])) die_nomem();
    if (dns4_ip4(&ip4_list, &tmp) < 0) die_dns_query1("SOA IP (IPv4)");
    for (j = 0; j < ip4_list.len; j++) {  /* only keep SOA IPs on host */
      ip4 = &ip4_list.va[j];
      if (ip4_vector_find(&ip4_list, ip4) == ip4_list.len) continue;
      if (!ip4_vector_append(&soa_ip4_list, ip4)) die_nomem();
    }
    if (dns6_ip6(&ip6_list, &tmp) < 0) die_dns_query1("SOA IP (IPv6)");
    for (j = 0; j < ip6_list.len; j++) {  /* only keep SOA IPs on host */
      ip6 = &ip6_list.va[j];
      if (ip6_vector_find(&ip6_list, ip6) == ip4_list.len) continue;
      if (!ip6_vector_append(&soa_ip6_list, ip6)) die_nomem();
    }
  }

  print_ip4_list(&soa_ip4_list, "SOA IP");
  print_ip6_list(&soa_ip6_list, "SOA IP");
  if (!soa_ip4_list.len && !soa_ip6_list.len) die_not_found("master servers", fqdn);
}

static void get_ns_name_list(void)
{
  if (flag_try_ip6_first) {
    if (dns6_ns(&ns_name_list, &domain) < 0) die_dns_query1("NS (IPv6)");
    if (!ns_name_list.len) {
      if (dns4_ns(&ns_name_list, &domain) < 0) die_dns_query1("NS (IPv4)");
    }
  }
  else {
    if (dns4_ns(&ns_name_list, &domain) < 0) die_dns_query1("NS (IPv4)");
    if (!ns_name_list.len) {
      if (dns6_ns(&ns_name_list, &domain) < 0) die_dns_query1("NS (IPv6)");
    }
  }
  sa_vector_lower(&ns_name_list);
  sa_vector_sort(&ns_name_list);
  print_name_list(&ns_name_list, "NS");
  if (!ns_name_list.len) die_rr_query("NS", fqdn);
}

static void get_ns_ip_list(void)
{
  register unsigned int i;
  register stralloc *sa;
  for (i = 0; i < ns_name_list.len; i++) {
    sa = &ns_name_list.va[i];
    if (!flag_notify_soa) {
      if (sa_vector_find(&soa_name_list, sa) < soa_name_list.len) continue;  /* skip SOA */
    }
    if (flag_try_ip6_first) {
      if (dns6_ip6(&ip6_list, sa) < 0) die_dns_query1("NS IP (IPv6)");
      if (ip6_list.len) {
        if (!ip6_vector_cat(&ns_ip6_list, &ip6_list)) die_nomem();
      }
      else {
        if (dns4_ip4(&ip4_list, sa) < 0) die_dns_query1("NS IP (IPv4)");
        if (!ip4_vector_cat(&ns_ip4_list, &ip4_list)) die_nomem();
      }
    }
    else {
      if (dns4_ip4(&ip4_list, sa) < 0) die_dns_query1("NS IP (IPv4)");
      if (ip4_list.len) {
        if (!ip4_vector_cat(&ns_ip4_list, &ip4_list)) die_nomem();
      }
      else {
        if (dns6_ip6(&ip6_list, sa) < 0) die_dns_query1("NS IP (IPv6)");
        if (!ip6_vector_cat(&ns_ip6_list, &ip6_list)) die_nomem();
      }
    }
  }
  print_ip4_list(&ns_ip4_list, "NS IP");
  print_ip6_list(&ns_ip6_list, "NS IP");
  if (!ns_ip4_list.len && !ns_ip6_list.len) die_not_found("secondary servers", fqdn);
}

static void notify_ip4_secondaries(void)
{
  register unsigned int i;
  register unsigned int j;
  ip4_address *sender_ip;
  ip4_address *recipient_ip;

  if (!ns_ip4_list.len) return;
  for (i = 0; i < soa_ip4_list.len; i++) {
    sender_ip = &soa_ip4_list.va[i];
    print_ip4(sender_ip, "sender");
    for (j = 0; j < ns_ip4_list.len; j++) {
      recipient_ip = &ns_ip4_list.va[j];
      if (flag_debug) {
	print_ip4(recipient_ip, "recipient info");
      }
      else {
	if (dns4_notify(sender_ip, &domain, recipient_ip) < 0) {
	  print_ip4(recipient_ip, "recipient fail");
	}
	else {
          print_ip4(recipient_ip, "recipient notified");
	}
      }
    }
  }
}

static void notify_ip6_secondaries(void)
{
  register unsigned int i;
  register unsigned int j;
  ip6_address *sender_ip;
  ip6_address *recipient_ip;

  if (!ns_ip6_list.len) return;
  for (i = 0; i < soa_ip6_list.len; i++) {
    sender_ip = &soa_ip6_list.va[i];
    print_ip6(sender_ip, "sender");
    for (j = 0; j < ns_ip6_list.len; j++) {
      recipient_ip = &ns_ip6_list.va[j];
      if (flag_debug) {
        print_ip6(recipient_ip, "recipient info");
      }
      else {
        if (dns6_notify(sender_ip, &domain, recipient_ip) < 0) {
	  print_ip6(recipient_ip, "recipient fail");
	}
	else {
          print_ip6(recipient_ip, "recipient notified");
	}
      }
    }
  }
}

static void do_notify(void)
{
  get_local_ip_list();
  get_soa_name_list();
  get_soa_ip_list();
  get_ns_name_list();
  get_ns_ip_list();
  notify_ip4_secondaries();
  notify_ip6_secondaries();
}

int main(int argc, char **argv)
{
  char seed[128];
  int opt;

  PROGRAM = *argv;
  dns_random_init(seed);

  while ((opt = getopt(argc, argv, "46ds")) != opteof) {
    switch (opt) {
      case '4':
        flag_try_ip6_first = 0;
        break;
      case '6':
        flag_try_ip6_first = 1;
        break;
      case 'd':
        flag_debug = 1;
        break;
      case 's':
        flag_notify_soa = 1;
        break;
      default:
        die_usage();
        break;
    }
  }
  argv += optind;

  fqdn = *argv;
  if (!fqdn || !*fqdn) die_usage1("FQDN not supplied");
  if (!stralloc_copys(&domain, fqdn)) die_nomem();
  do_notify();
  _exit(0);
}
