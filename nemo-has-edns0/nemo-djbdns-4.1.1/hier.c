#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/install.h>

#include "auto_prefix.h"

void hier(void);

void hier(void)
{
/*
  c("/", "etc", "dnsroots.global", (uid_t)-1, (gid_t)-1, 0644);
*/
  h(auto_prefix, (uid_t)-1, (gid_t)-1, 0755);
  d(auto_prefix, "bin", (uid_t)-1, (gid_t)-1, 0755);
  d(auto_prefix, "sbin", (uid_t)-1, (gid_t)-1, 0755);
  d(auto_prefix, "include", (uid_t)-1, (gid_t)-1, 0755);
  d(auto_prefix, "include/nemo", (uid_t)-1, (gid_t)-1, 0755);
  d(auto_prefix, "man", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/man1", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/man3", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/man5", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/man8", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/cat1", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/cat3", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/cat5", (uid_t)install_manuid, (gid_t)-1, 0755);
  d(auto_prefix, "man/cat8", (uid_t)install_manuid, (gid_t)-1, 0755);

  c(auto_prefix, "bin", "axfrdns-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "axfrdns6-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dbldns-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dbldns6-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache6-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "rbldns-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "rbldns6-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns6-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "walldns-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "walldns6-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "wilddns-conf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "wilddns6-conf", (uid_t)-1, (gid_t)-1, 0755);

  c(auto_prefix, "man/man8", "axfrdns-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "axfrdns6-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dbldns-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dbldns6-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache6-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "rbldns-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "rbldns6-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns6-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "walldns-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "walldns6-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "wilddns-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "wilddns6-conf.8", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "man/cat8", "axfrdns-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dbldns-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dbldns6-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache6-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "rbldns-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "rbldns6-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns6-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "walldns-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "walldns6-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "wilddns-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "wilddns6-conf.0", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "sbin", "axfrdns", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "axfrdns6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "dbldns", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "dbldns6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "dnscache", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "dnscache6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "rbldns", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "rbldns6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "tinydns", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "tinydns6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "walldns", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "walldns6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "wilddns", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "sbin", "wilddns6", (uid_t)-1, (gid_t)-1, 0755);

  c(auto_prefix, "man/man8", "axfrdns.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "axfrdns6.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dbldns.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dbldns6.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache6.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "rbldns.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "rbldns6.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns6.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "walldns.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "walldns6.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "wilddns.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "wilddns6.8", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "man/cat8", "axfrdns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "axfrdns6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dbldns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dbldns6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "rbldns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "rbldns6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "walldns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "walldns6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "wilddns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "wilddns6.0", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "bin", "axfr-get", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "axfr-notify", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dbldns-data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache-data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache6-data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache-dnlist2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache-dnlist2roots", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache6-dnlist2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache6-dnlist2roots", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache-iplist2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnscache6-iplist2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "rbldns-data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "rbldns6-data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-bind2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-dnlist2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-edit", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-get", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-v1data2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "tinydns-v3data2data", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "wilddns-data", (uid_t)-1, (gid_t)-1, 0755);

  c(auto_prefix, "man/man8", "axfr-get.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "axfr-notify.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dbldns-data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache-data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache6-data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache-dnlist2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache6-dnlist2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache-iplist2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "dnscache6-iplist2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "rbldns-data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "rbldns6-data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns-bind2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns-data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns-dnlist2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns-edit.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns-v1data2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "tinydns-v3data2data.8", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man8", "wilddns-data.8", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "man/cat8", "axfr-get.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "axfr-notify.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dbldns-data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache-data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache6-data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache-dnlist2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache6-dnlist2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache-iplist2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "dnscache6-iplist2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "rbldns-data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "rbldns6-data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns-bind2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns-data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns-dnlist2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns-edit.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns-v1data2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "tinydns-v3data2data.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat8", "wilddns-data.0", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "bin", "dblcheck", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dblcheck6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsip", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsip6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsipq", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsip6q", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsname", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnstxt", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsspf", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsmx", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsmxip", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsmxip6", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsfilter", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "random-ip", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsqr", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnsq", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnstrace", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "dnstracesort", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "rbl", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "rblcheck", (uid_t)-1, (gid_t)-1, 0755);
  c(auto_prefix, "bin", "rblcheck6", (uid_t)-1, (gid_t)-1, 0755);

  c(auto_prefix, "man/man5", "qualification.5", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat5", "qualification.0", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "man/man3", "djbdns.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_domain.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_domain_cat.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_domain_copy.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_domain_diff.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_domain_equal.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_domain_fromdot.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_domain_length.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ip4_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ip4_qualify.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ip4.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ip6_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ip6_qualify.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ip6.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_mx_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_mx.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_name_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_name4.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_name6.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ns.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_ns_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_random.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_soa_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_soa.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_spf.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_txt_packet.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns_txt.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns4_transmit.3", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man3", "dns6_transmit.3", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "man/cat3", "djbdns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_domain.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_domain_cat.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_domain_copy.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_domain_diff.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_domain_equal.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_domain_fromdot.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_domain_length.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ip4_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ip4_qualify.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ip4.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ip6_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ip6_qualify.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ip6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_mx_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_mx.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_name_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_name4.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_name6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ns.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_ns_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_random.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_soa_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_soa.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_spf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_txt_packet.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns_txt.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns4_transmit.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat3", "dns6_transmit.0", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "man/man1", "dblcheck.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dblcheck6.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsip.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsip6.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsipq.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsip6q.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsname.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnstxt.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsspf.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsmx.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsmxip.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsmxip6.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsfilter.1", (uid_t)install_manuid, (gid_t)-1, 0644);
/*
  c(auto_prefix, "man/man1", "random-ip.1", (uid_t)install_manuid, (gid_t)-1, 0644);
*/
  c(auto_prefix, "man/man1", "dnsqr.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnsq.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnstrace.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "dnstracesort.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "rblcheck.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "rblcheck6.1", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/man1", "tinydns-get.1", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "man/cat1", "dblcheck.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dblcheck6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsip.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsip6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsipq.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsip6q.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsname.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsspf.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsmx.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsmxip.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsmxip6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsfilter.0", (uid_t)install_manuid, (gid_t)-1, 0644);
/*
  c(auto_prefix, "man/cat1", "random-ip.0", (uid_t)install_manuid, (gid_t)-1, 0644);
*/
  c(auto_prefix, "man/cat1", "dnsqr.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnsq.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "dnstrace.0", (uid_t)install_manuid, (gid_t)-1, 0644);
/*
  c(auto_prefix, "man/cat1", "dnstracesort.0", (uid_t)install_manuid, (gid_t)-1, 0644);
*/
  c(auto_prefix, "man/cat1", "rblcheck.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "rblcheck6.0", (uid_t)install_manuid, (gid_t)-1, 0644);
  c(auto_prefix, "man/cat1", "tinydns-get.0", (uid_t)install_manuid, (gid_t)-1, 0644);

  c(auto_prefix, "include/nemo", "dns.h", (uid_t)-1, (gid_t)-1, 0644);
  c(auto_prefix, "lib", "libdjbdns.a", (uid_t)-1, (gid_t)-1, 0644);
}
