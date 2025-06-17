# Don't edit Makefile! Use conf-* for configuration.

SHELL=/bin/sh

default: it

it: \
libs debug.o prog man test

setup: \
libs prog man install
	./install

check: \
libs prog man instcheck
	./instcheck

clean: \
clean-all
	./clean-all

clean-all: \
clean-all.sh
	cat warn-auto.sh clean-all.sh > clean-all
	chmod 755 clean-all

cppcheck:
	cppcheck \
	-I/usr/include \
	-I/usr/local/include \
	--library=bsd.cfg \
	--library=posix.cfg \
	--inconclusive \
	--enable=warning,performance,portability,style \
	--check-config \
	--force \
	--quiet \
	*.c

compile: \
print-cc.sh warn-auto.sh conf-cc
	rm -f compile
	sh print-cc.sh > compile
	chmod 700 compile

load: \
print-ld.sh warn-auto.sh conf-ld
	rm -f load
	sh print-ld.sh > load
	chmod 700 load

address4_vector.o: \
compile address4_vector.c dns.h address4_vector.h
	./compile address4_vector.c

address6_vector.o: \
compile address6_vector.c dns.h address6_vector.h
	./compile address6_vector.c

auto_prefix.c: \
conf-prefix
	c-auto-str auto_prefix `head -n 1 conf-prefix` > auto_prefix.c

auto_prefix.o: \
compile auto_prefix.c
	./compile auto_prefix.c

axfr-get.8: \
sedit axfr-get.mdoc
	./sedit axfr-get.mdoc > axfr-get.8

axfr-get.0: \
mancat axfr-get.8
	./mancat axfr-get.8 > axfr-get.0

axfr-get: \
load axfr-get.o safe.a die.a libdjbdns.a
	./load axfr-get safe.a die.a libdjbdns.a

axfr-get.o: \
compile axfr-get.c dns.h die.h safe.h
	./compile axfr-get.c

axfr-notify.8: \
sedit axfr-notify.mdoc
	./sedit axfr-notify.mdoc > axfr-notify.8

axfr-notify.0: \
mancat axfr-notify.8
	./mancat axfr-notify.8 > axfr-notify.0

axfr-notify: \
load axfr-notify.o safe.a die.a libdjbdns.a
	./load axfr-notify safe.a die.a libdjbdns.a

axfr-notify.o: \
compile axfr-notify.c dns.h die.h safe.h
	./compile axfr-notify.c

axfrdns.8: \
sedit axfrdns.mdoc
	./sedit axfrdns.mdoc > axfrdns.8

axfrdns.0: \
mancat axfrdns.8
	./mancat axfrdns.8 > axfrdns.0

axfrdns.o: \
compile axfrdns.c droproot.h dns.h qlog.h response.h respond.h die.h safe.h \
data_cdb.h tdlookup.h
	./compile axfrdns.c

axfrdns: \
load axfrdns.o droproot.o tdlookup4.o tdlookup_loc_setup.o tdlookup.o \
data_cdb.o qlog4.o qlog.o response.a safe.a die.a libdjbdns.a
	./load axfrdns droproot.o tdlookup4.o tdlookup_loc_setup.o tdlookup.o \
	data_cdb.o qlog4.o qlog.o response.a safe.a die.a libdjbdns.a

axfrdns-conf.8: \
sedit axfrdns-conf.mdoc
	./sedit axfrdns-conf.mdoc > axfrdns-conf.8

axfrdns-conf.0: \
mancat axfrdns-conf.8
	./mancat axfrdns-conf.8 > axfrdns-conf.0

axfrdns-conf: \
load axfrdns-conf.o generic-conf.o auto_prefix.o die.a
	./load axfrdns-conf generic-conf.o auto_prefix.o die.a

axfrdns-conf.o: \
compile axfrdns-conf.c auto_prefix.h generic-conf.h die.h
	./compile axfrdns-conf.c

axfrdns6.8: \
sedit axfrdns6.mdoc
	./sedit axfrdns6.mdoc > axfrdns6.8

axfrdns6.0: \
mancat axfrdns6.8
	./mancat axfrdns6.8 > axfrdns6.0

axfrdns6.o: \
compile axfrdns6.c droproot.h dns.h qlog.h response.h respond.h die.h safe.h \
data_cdb.h tdlookup.h
	./compile axfrdns6.c

axfrdns6: \
load axfrdns6.o droproot.o tdlookup6.o tdlookup_loc_setup.o tdlookup.o \
data_cdb.o qlog6.o qlog.o response.a safe.a die.a libdjbdns.a
	./load axfrdns6 droproot.o tdlookup6.o tdlookup_loc_setup.o \
	tdlookup.o data_cdb.o qlog6.o qlog.o response.a safe.a die.a \
	libdjbdns.a

axfrdns6-conf.8: \
sedit axfrdns6-conf.mdoc
	./sedit axfrdns6-conf.mdoc > axfrdns6-conf.8

axfrdns6-conf.0: \
mancat axfrdns6-conf.8
	./mancat axfrdns6-conf.8 > axfrdns6-conf.0

axfrdns6-conf: \
load axfrdns6-conf.o generic-conf.o auto_prefix.o die.a
	./load axfrdns6-conf generic-conf.o auto_prefix.o die.a

axfrdns6-conf.o: \
compile axfrdns6-conf.c auto_prefix.h generic-conf.h die.h
	./compile axfrdns6-conf.c

byte_domain_length.o: \
compile byte_domain_length.c dns.h
	./compile byte_domain_length.c

cache.a: \
makelib cache.o cache_generic.o cache_get_rr_aaaa.o cache_get_rr_a.o \
cache_get_rr_cname.o cache_get_rr_ns.o cache_test_rr.o cache_expire_rr.o \
cache_mark.o cache_make_key.o cache_set_info.o
	./makelib cache.a cache_get_rr_aaaa.o cache_get_rr_a.o \
	cache_get_rr_cname.o cache_get_rr_ns.o cache_test_rr.o \
	cache_mark.o cache_generic.o cache_expire_rr.o cache_set_info.o \
	cache_make_key.o cache.o

cache.o: \
compile cache.c cache.h dns.h dnscache.h dn_vector.h log.h
	./compile cache.c

cache_expire_rr.o: \
compile cache_expire_rr.c cache.h dns.h dn_vector.h
	./compile cache_expire_rr.c

cache_generic.o: \
compile cache_generic.c cache.h dns.h dn_vector.h
	./compile cache_generic.c

cache_get_rr_a.o: \
compile cache_get_rr_a.c cache.h dns.h die.h dn_vector.h
	./compile cache_get_rr_a.c

cache_get_rr_aaaa.o: \
compile cache_get_rr_aaaa.c cache.h dns.h die.h dn_vector.h
	./compile cache_get_rr_aaaa.c

cache_get_rr_cname.o: \
compile cache_get_rr_cname.c cache.h dns.h safe.h dn_vector.h
	./compile cache_get_rr_cname.c

cache_get_rr_ns.o: \
compile cache_get_rr_ns.c cache.h dns.h die.h safe.h dn_vector.h
	./compile cache_get_rr_ns.c

cache_make_key.o: \
compile cache_make_key.c cache.h dns.h die.h dn_vector.h
	./compile cache_make_key.c

cache_mark.o: \
compile cache_mark.c cache.h dns.h dn_vector.h
	./compile cache_mark.c

cache_set_info.o: \
compile cache_set_info.c cache.h dns.h log.h dn_vector.h
	./compile cache_set_info.c

cache_test_rr.o: \
compile cache_test_rr.c cache.h dns.h dn_vector.h
	./compile cache_test_rr.c

cachetest: \
load cachetest.o cache.o dn_vector.o log.a libdjbdns.a
	./load cachetest cache.o dn_vector.o log.a libdjbdns.a

cachetest.o: \
compile cachetest.c cache.h
	./compile cachetest.c

chkshsgr: \
load chkshsgr.o safe.a die.a
	./load chkshsgr

client4.o: \
compile client4.c cache.h client.h client4.h dnscache.h dns.h dn_vector.h \
query.h query4.h ioquery4.h tcpclient4.h udpclient4.h client.c die.h
	./compile client4.c

client4_answer.o: \
compile client4_answer.c cache.h client.h client4.h dnscache.h dn_vector.h \
dns.h query.h query4.h die.h ioquery4.h tcpclient4.h udpclient4.h \
log.h safe.h client_answer.c response.h
	./compile client4_answer.c

client6.o: \
compile client6.c cache.h client.h client6.h dnscache.h dns.h dn_vector.h \
query.h query6.h ioquery6.h tcpclient6.h udpclient6.h client.c die.h
	./compile client6.c

client6_answer.o: \
compile client_answer.c cache.h client.h client6.h dnscache.h dn_vector.h \
dns.h query.h query6.h die.h ioquery6.h tcpclient6.h udpclient6.h \
log.h safe.h client_answer.c response.h
	./compile client6_answer.c

chkshsgr.o: \
compile chkshsgr.c
	./compile chkshsgr.c

data_cdb.o: \
compile data_cdb.c data_cdb.h die.h
	./compile data_cdb.c

dblcheck.1: \
sedit dblcheck.mdoc
	./sedit dblcheck.mdoc > dblcheck.1

dblcheck.0: \
mancat dblcheck.1
	./mancat dblcheck.1 > dblcheck.0

dblcheck: \
load dblcheck.o die.a libdjbdns.a socket.lib
	./load dblcheck die.a libdjbdns.a `cat socket.lib`

dblcheck.o: \
compile dblcheck.c dns.h die.h
	./compile dblcheck.c

dblcheck6.1: \
sedit dblcheck6.mdoc
	./sedit dblcheck6.mdoc > dblcheck6.1

dblcheck6.0: \
mancat dblcheck6.1
	./mancat dblcheck6.1 > dblcheck6.0

dblcheck6: \
load dblcheck6.o die.a libdjbdns.a socket.lib
	./load dblcheck6 die.a libdjbdns.a `cat socket.lib`

dblcheck6.o: \
compile dblcheck6.c dns.h die.h
	./compile dblcheck6.c

dbldns.8: \
sedit dbldns.mdoc
	./sedit dbldns.mdoc > dbldns.8

dbldns.0: \
mancat dbldns.8
	./mancat dbldns.8 > dbldns.0

dbldns: \
load dbldns.o server4.o dd4.o droproot.o qlog4.o qlog.o dbllookup.o \
data_cdb.o response.a safe.a die.a libdjbdns.a socket.lib
	./load dbldns dbllookup.o data_cdb.o server4.o dd4.o droproot.o \
	qlog4.o qlog.o response.a safe.a die.a libdjbdns.a \
	`cat socket.lib`

dbldns.o: \
compile dbldns.c dns.h respond.h dbllookup.h data_cdb.h
	./compile dbldns.c

dbldns-conf.8: \
sedit dbldns-conf.mdoc
	./sedit dbldns-conf.mdoc > dbldns-conf.8

dbldns-conf.0: \
mancat dbldns-conf.8
	./mancat dbldns-conf.8 > dbldns-conf.0

dbldns-conf: \
load dbldns-conf.o generic-conf.o auto_prefix.o die.a
	./load dbldns-conf generic-conf.o auto_prefix.o die.a

dbldns-conf.o: \
compile dbldns-conf.c auto_prefix.h generic-conf.h die.h
	./compile dbldns-conf.c

dbldns6.8: \
sedit dbldns6.mdoc
	./sedit dbldns6.mdoc > dbldns6.8

dbldns6.0: \
mancat dbldns6.8
	./mancat dbldns6.8 > dbldns6.0

dbldns6: \
load dbldns6.o server6.o dd6.o droproot.o qlog6.o qlog.o dbllookup.o \
data_cdb.o response.a safe.a die.a libdjbdns.a socket.lib
	./load dbldns6 dbllookup.o data_cdb.o server6.o dd6.o droproot.o \
	qlog6.o qlog.o response.a safe.a die.a libdjbdns.a \
	`cat socket.lib`

dbldns6.o: \
compile dbldns6.c dns.h respond.h dbllookup.h data_cdb.h
	./compile dbldns6.c

dbldns6-conf.8: \
sedit dbldns6-conf.mdoc
	./sedit dbldns6-conf.mdoc > dbldns6-conf.8

dbldns6-conf.0: \
mancat dbldns6-conf.8
	./mancat dbldns6-conf.8 > dbldns6-conf.0

dbldns6-conf: \
load dbldns6-conf.o generic-conf.o auto_prefix.o die.a
	./load dbldns6-conf generic-conf.o auto_prefix.o die.a

dbldns6-conf.o: \
compile dbldns6-conf.c auto_prefix.h generic-conf.h die.h
	./compile dbldns6-conf.c

dbldns-data.8: \
sedit dbldns-data.mdoc
	./sedit dbldns-data.mdoc > dbldns-data.8

dbldns-data.0: \
mancat dbldns-data.8
	./mancat dbldns-data.8 > dbldns-data.0

dbldns-data: \
load dbldns-data.o whitespace.o die.a libdjbdns.a
	./load dbldns-data whitespace.o die.a libdjbdns.a

dbldns-data.o: \
compile dbldns-data.c whitespace.h dns.h die.h
	./compile dbldns-data.c

dbllookup.o: \
compile dbllookup.c dns.h response.h respond.h dbllookup.h die.h data_cdb.h
	./compile dbllookup.c

dd4.o: \
compile dd4.c dns.h dd.h die.h
	./compile dd4.c

dd6.o: \
compile dd6.c dns.h dd.h die.h
	./compile dd6.c

die.a: \
makelib die_nomem.o die_usage.o die_bogus_query.o die_dns_query.o die_read.o \
die_write.o die_move.o die_env.o die_parse.o die_create.o die_open.o die.o \
die_chdir.o die_not_found.o die_unknown_account.o die_stat.o die_dns_query1.o \
die_bind.o die_create2.o die_chmod.o die_setgid.o die_setuid.o die_syntax.o \
die_create_device.o die_sys.o die_usage1.o die_internal.o die_chroot.o \
die_rr_query.o die_dnscache.o die1.o die_read_line.o die_servers.o
	./makelib die.a die_dnscache.o die_bogus_query.o die_nomem.o \
	die_usage.o die_dns_query.o die_read_line.o die_read.o die_write.o \
	die_env.o die_move.o die_parse.o die_create.o die_open.o die_chdir.o \
	die_not_found.o die_stat.o die_unknown_account.o die_dns_query1.o \
	die_bind.o die_create2.o die_chmod.o die_setgid.o die_setuid.o \
	die_create_device.o die_sys.o die_syntax.o die_usage1.o die_servers.o \
	die_internal.o die_chroot.o die_rr_query.o die1.o die.o

die.o: \
compile die.c die.h
	./compile die.c

die1.o: \
compile die1.c die.h
	./compile die1.c

die_bind.o: \
compile die_bind.c die.h
	./compile die_bind.c

die_bogus_query.o: \
compile die_bogus_query.c die.h
	./compile die_bogus_query.c

die_chdir.o: \
compile die_chdir.c die.h
	./compile die_chdir.c

die_chmod.o: \
compile die_chmod.c die.h
	./compile die_chmod.c

die_chroot.o: \
compile die_chroot.c die.h
	./compile die_chroot.c

die_create.o: \
compile die_create.c die.h
	./compile die_create.c

die_create2.o: \
compile die_create2.c die.h
	./compile die_create2.c

die_create_device.o: \
compile die_create_device.c die.h
	./compile die_create_device.c

die_dnscache.o: \
compile die_dnscache.c die.h
	./compile die_dnscache.c

die_env.o: \
compile die_env.c die.h
	./compile die_env.c

die_dns_query.o: \
compile die_dns_query.c die.h
	./compile die_dns_query.c

die_dns_query1.o: \
compile die_dns_query1.c die.h
	./compile die_dns_query1.c

die_internal.o: \
compile die_internal.c die.h
	./compile die_internal.c

die_move.o: \
compile die_move.c die.h
	./compile die_move.c

die_nomem.o: \
compile die_nomem.c die.h
	./compile die_nomem.c

die_not_found.o: \
compile die_not_found.c die.h
	./compile die_not_found.c

die_open.o: \
compile die_open.c die.h
	./compile die_open.c

die_parse.o: \
compile die_parse.c die.h
	./compile die_parse.c

die_read.o: \
compile die_read.c die.h
	./compile die_read.c

die_read_line.o: \
compile die_read_line.c die.h
	./compile die_read_line.c

die_rr_query.o: \
compile die_rr_query.c die.h
	./compile die_rr_query.c

die_servers.o: \
compile die_servers.c die.h
	./compile die_servers.c

die_setgid.o: \
compile die_setgid.c die.h
	./compile die_setgid.c

die_setuid.o: \
compile die_setuid.c die.h
	./compile die_setuid.c

die_stat.o: \
compile die_stat.c die.h
	./compile die_stat.c

die_syntax.o: \
compile die_syntax.c die.h
	./compile die_syntax.c

die_sys.o: \
compile die_sys.c die.h
	./compile die_sys.c

die_unknown_account.o: \
compile die_unknown_account.c die.h
	./compile die_unknown_account.c

die_usage.o: \
compile die_usage.c die.h
	./compile die_usage.c

die_usage1.o: \
compile die_usage1.c die.h
	./compile die_usage1.c

die_write.o: \
compile die_write.c die.h
	./compile die_write.c

djbdns.3: \
sedit djbdns.mdoc
	./sedit djbdns.mdoc > djbdns.3

djbdns.0: \
mancat djbdns.3
	./mancat djbdns.3 > djbdns.0

libdjbdns.a: \
makelib dns_domain_suffixpos.o dns_domain_suffix.o dns_domain_drop1label.o \
byte_domain_length.o dns_domain_fromdot.o dns4_ip6.o dns_domain_ok.o \
dns_domain_pack.o dns_domain_unpack.o dns_domain_copy.o dns_domain_copyb.o \
dns_domain_erase.o dns_domain_ready.o dns_domain_equal.o dns_domain_lower.o \
dns_domain_todot_cat.o dns6_ip6.o dns6_ip4.o dns4_ip4.o dns_domain_catb.o \
dns6_ip6_qualify.o dns4_ip6_qualify.o dns6_ip4_qualify.o dns4_ip4_qualify.o \
dns6_mx.o dns4_mx.o dns_mx_packet.o dns6_mxip6.o dns4_mxip6.o dns4_name6.o \
dns4_mxip4.o dns6_mxip4.o dns6_name6.o dns6_name6.o dns6_name4.o dns4_name4.o \
dns_name_packet.o dns_name6_domain.o dns_name4_domain.o dns_packet.o \
dns_random.o dns_rcip6.o dns_rcip4.o dns_rcrw.o dns6_resolve.o dns4_resolve.o \
dns_sortip6.o dns_sortip4.o dns6_transmit_start_edns0.o \
dns6_transmit_start_notify.o dns6_transmit_start.o dns6_transmit.o \
dns4_transmit_start_edns0.o dns4_transmit_start_notify.o \
dns4_transmit_start.o dns4_transmit.o dns6_txt.o dns4_txt.o dns_txt_packet.o \
dns6_spf.o dns4_spf.o dns_domain_diff.o dns_qualify_do_rule.o \
mxname_vector_remove.o mxname_vector_append.o mxname_vector_erase.o \
mxname_vector_ready.o mxip6_vector_append.o mxip6_vector_erase.o \
mxip6_vector_ready.o mxip4_vector_append.o dns6_ns.o mxip4_vector_erase.o \
mxip4_vector_ready.o dns_type_equalb.o dns_type_equal.o dns_type_zero.o \
dns_type_diffb.o dns_type_diff.o dns_type_set.o dns4_ns.o dns_type_get.o \
dns_type_pack.o dns_type_unpack.o dns_type_copy.o dns_type_parse.o \
dns_class_equalb.o dns_class_equal.o dns_class_zero.o dns_class_diffb.o \
dns_class_diff.o dns_class_pack.o dns_id_unpack.o dns_class_unpack.o \
dns_class_copy.o dns_id_pack.o dns_type_str.o dns_domain_labellength.o \
dns_domain_free.o dns_domain_cat.o dns_domain_active.o dns_ip4_packet.o \
dns_ip6_packet.o dns_soa_packet.o mxip_vector_sort46.o mxip_vector_sort64.o \
mxip_vector_swap.o dns4_soa.o mxip_vector_append6.o mxip_vector_append4.o \
mxip_vector_cat6.o dns6_soa.o mxip_vector_cat4.o mxip_vector_ready.o \
mxip_data_diff46.o mxip_data_diff64.o mxip4_data_diff.o mxip6_data_diff.o \
mxip6_vector_sort.o mxip6_vector_swap.o mxip4_vector_sort.o \
mxip4_vector_swap.o mxname_data_diff.o dns6_notify.o mxname_vector_sort.o \
mxname_vector_swap.o dns4_notify.o soa_vector_append.o soa_vector_erase.o \
soa_vector_ready.o dns_ns_packet.o dns_domain_labelcount.o dns_d_empty.o \
dns_d_ip4_localhost.o dns_d_any_inaddr_arpa.o dns_d_localhost_inaddr_arpa.o \
dns_t_nil.o dns_d_base_inaddr_arpa.o dns_d_ip6_localhost.o \
dns_d_ip6_localnet.o dns_d_ip6_mcastprefix.o dns_d_ip6_allnodes.o \
dns_d_ip6_allrouters.o dns_d_ip6_allhosts.o dns_d_any_ip6_arpa.o \
dns_d_localhost_ip6_arpa.o dns_d_localnet_ip6_arpa.o whitespace.o \
dns_d_mcastprefix_ip6_arpa.o dns_d_allnodes_ip6_arpa.o dns_c_in.o dns_t_a.o \
dns_d_allrouters_ip6_arpa.o dns_d_allhosts_ip6_arpa.o dns_d_base_ip6_arpa.o \
dns_c_any.o dns_t_ns.o dns_t_cname.o dns_t_soa.o dns_t_ptr.o dns_t_hinfo.o \
dns_t_mx.o dns_t_txt.o dns_t_rp.o dns_t_sig.o dns_t_key.o dns_t_aaaa.o \
dns_t_loc.o dns_t_srv.o dns_t_naptr.o dns_t_opt.o dns_t_spf.o dns_t_ixfr.o \
dns_t_axfr.o dns_t_caa.o dns_t_any.o dns_t_ds.o dns_t_rrsig.o dns_t_nsec.o \
dns_t_dnskey.o dns_idna_encode.o dns_rcode_str.o dns_domain_labelparse.o
	./makelib libdjbdns.a \
	dns6_spf.o dns4_spf.o dns6_mxip6.o dns4_mxip6.o dns6_mxip4.o \
	dns4_mxip4.o dns6_ip6_qualify.o dns4_ip6_qualify.o dns6_ip4_qualify.o \
	dns4_ip4_qualify.o dns_qualify_do_rule.o dns_id_pack.o dns6_soa.o \
	dns_id_unpack.o dns6_ip6.o dns4_ip6.o dns6_ip4.o dns4_ip4.o \
	dns4_soa.o dns6_ns.o dns4_ns.o dns_ns_packet.o dns6_mx.o dns4_mx.o \
	dns_mx_packet.o dns6_name6.o dns4_name6.o dns6_name4.o dns4_name4.o \
	dns6_txt.o dns4_txt.o dns_txt_packet.o dns_ip4_packet.o \
	dns_ip6_packet.o dns_name_packet.o dns_soa_packet.o \
	dns_name6_domain.o dns_name4_domain.o dns_packet.o dns_random.o \
	dns_rcip6.o dns_rcip4.o dns_rcrw.o dns6_notify.o dns4_notify.o \
	dns6_resolve.o dns4_resolve.o dns_sortip6.o dns_idna_encode.o \
	dns_sortip4.o dns6_transmit_start_edns0.o \
	dns6_transmit_start_notify.o dns6_transmit_start.o dns6_transmit.o \
	dns4_transmit_start_edns0.o dns4_transmit_start_notify.o \
	dns4_transmit_start.o dns4_transmit.o dns_domain_suffixpos.o \
	dns_domain_suffix.o dns_domain_drop1label.o dns_domain_fromdot.o \
	dns_domain_pack.o dns_domain_ok.o dns_domain_cat.o dns_domain_catb.o \
	dns_domain_unpack.o dns_domain_copy.o dns_domain_copyb.o \
	dns_domain_erase.o dns_domain_ready.o dns_domain_diff.o \
	dns_domain_equal.o dns_domain_lower.o dns_domain_labelparse.o \
	dns_domain_labelcount.o dns_domain_todot_cat.o mxname_vector_remove.o \
	mxname_vector_append.o mxname_vector_erase.o mxname_vector_ready.o \
	mxname_vector_sort.o mxname_vector_swap.o mxname_data_diff.o \
	mxip_vector_sort46.o mxip_vector_sort64.o mxip_vector_swap.o \
	mxip_vector_append6.o mxip_vector_append4.o mxip_vector_cat6.o \
	mxip_vector_cat4.o mxip_vector_ready.o mxip_data_diff46.o \
	mxip_data_diff64.o mxip6_vector_sort.o mxip6_vector_swap.o \
	mxip6_vector_append.o mxip6_vector_erase.o mxip6_vector_ready.o \
	mxip4_vector_sort.o mxip4_vector_swap.o mxip4_vector_append.o \
	mxip4_vector_erase.o mxip4_vector_ready.o mxip4_data_diff.o \
	mxip6_data_diff.o soa_vector_append.o soa_vector_erase.o \
	soa_vector_ready.o dns_type_equalb.o dns_type_equal.o \
	dns_type_diffb.o dns_type_diff.o dns_type_zero.o dns_type_set.o \
	dns_type_get.o dns_type_pack.o dns_type_unpack.o dns_type_copy.o \
	dns_type_str.o dns_type_parse.o dns_class_equalb.o dns_class_equal.o \
	dns_class_diffb.o dns_class_diff.o dns_class_unpack.o \
	dns_class_zero.o dns_class_pack.o dns_class_copy.o \
	byte_domain_length.o dns_domain_labellength.o dns_domain_free.o \
	dns_domain_active.o dns_d_empty.o dns_d_ip4_localhost.o \
	dns_d_localhost_inaddr_arpa.o dns_d_any_inaddr_arpa.o \
	dns_d_base_inaddr_arpa.o dns_d_ip6_localhost.o dns_d_ip6_localnet.o \
	dns_d_ip6_mcastprefix.o dns_d_ip6_allnodes.o dns_d_ip6_allrouters.o \
	dns_d_ip6_allhosts.o dns_d_any_ip6_arpa.o dns_d_localhost_ip6_arpa.o \
	dns_c_in.o dns_t_mx.o dns_d_localnet_ip6_arpa.o dns_c_any.o \
	dns_t_nil.o dns_t_a.o dns_d_mcastprefix_ip6_arpa.o \
	dns_d_allnodes_ip6_arpa.o dns_t_ns.o dns_d_allrouters_ip6_arpa.o \
	dns_d_allhosts_ip6_arpa.o dns_t_cname.o dns_d_base_ip6_arpa.o \
	dns_t_soa.o dns_t_ptr.o dns_t_hinfo.o dns_t_txt.o dns_t_rp.o \
	dns_t_sig.o dns_t_key.o dns_t_aaaa.o dns_t_loc.o dns_t_srv.o \
	dns_t_naptr.o dns_t_opt.o dns_t_spf.o dns_t_ixfr.o dns_t_axfr.o \
	dns_t_caa.o dns_t_any.o dns_t_ds.o dns_t_rrsig.o dns_t_nsec.o \
	dns_t_dnskey.o dns_rcode_str.o whitespace.o

dn_vector.o: \
compile dn_vector.c dns.h dn_vector.h
	./compile dn_vector.c

dns_ip4_packet.3: \
sedit dns_ip4_packet.mdoc
	./sedit dns_ip4_packet.mdoc > dns_ip4_packet.3

dns_ip4_packet.0: \
mancat dns_ip4_packet.3
	./mancat dns_ip4_packet.3 > dns_ip4_packet.0

dns_ip4_packet.o: \
compile dns_ip4_packet.c dns.h
	./compile dns_ip4_packet.c

dns_ip4_qualify.3: \
sedit dns_ip4_qualify.mdoc
	./sedit dns_ip4_qualify.mdoc > dns_ip4_qualify.3

dns_ip4_qualify.0: \
mancat dns_ip4_qualify.3
	./mancat dns_ip4_qualify.3 > dns_ip4_qualify.0

dns_ip4.3: \
sedit dns_ip4.mdoc
	./sedit dns_ip4.mdoc > dns_ip4.3

dns_ip4.0: \
mancat dns_ip4.3
	./mancat dns_ip4.3 > dns_ip4.0

dns4_ip4.o: \
compile dns4_ip4.c dns.h
	./compile dns4_ip4.c

dns6_ip4.o: \
compile dns6_ip4.c dns.h
	./compile dns6_ip4.c

dns_qualify_do_rule.o: \
compile dns_qualify_do_rule.c dns.h
	./compile dns_qualify_do_rule.c

dns4_ip4_qualify.o: \
compile dns4_ip4_qualify.c dns.h
	./compile dns4_ip4_qualify.c

dns6_ip4_qualify.o: \
compile dns6_ip4_qualify.c dns.h
	./compile dns6_ip4_qualify.c

dns_ip6_packet.3: \
sedit dns_ip6_packet.mdoc
	./sedit dns_ip6_packet.mdoc > dns_ip6_packet.3

dns_ip6_packet.0: \
mancat dns_ip6_packet.3
	./mancat dns_ip6_packet.3 > dns_ip6_packet.0

dns_ip6_packet.o: \
compile dns_ip6_packet.c dns.h
	./compile dns_ip6_packet.c

dns_ip6_qualify.3: \
sedit dns_ip6_qualify.mdoc
	./sedit dns_ip6_qualify.mdoc > dns_ip6_qualify.3

dns_ip6_qualify.0: \
mancat dns_ip6_qualify.3
	./mancat dns_ip6_qualify.3 > dns_ip6_qualify.0

dns_ip6.3: \
sedit dns_ip6.mdoc
	./sedit dns_ip6.mdoc > dns_ip6.3

dns_ip6.0: \
mancat dns_ip6.3
	./mancat dns_ip6.3 > dns_ip6.0

dns4_ip6.o: \
compile dns4_ip6.c dns.h
	./compile dns4_ip6.c

dns6_ip6.o: \
compile dns6_ip6.c dns.h
	./compile dns6_ip6.c

dns4_ip6_qualify.o: \
compile dns4_ip6_qualify.c dns.h
	./compile dns4_ip6_qualify.c

dns6_ip6_qualify.o: \
compile dns6_ip6_qualify.c dns.h
	./compile dns6_ip6_qualify.c

dns_c_in.o: \
compile dns_c_in.c dns.h
	./compile dns_c_in.c

dns_c_any.o: \
compile dns_c_any.c dns.h
	./compile dns_c_any.c

dns_class_copy.o: \
compile dns_class_copy.c dns.h
	./compile dns_class_copy.c

dns_class_unpack.o: \
compile dns_class_unpack.c dns.h
	./compile dns_class_unpack.c

dns_class_pack.o: \
compile dns_class_pack.c dns.h
	./compile dns_class_pack.c

dns_class_equal.o: \
compile dns_class_equal.c dns.h
	./compile dns_class_equal.c

dns_class_equalb.o: \
compile dns_class_equalb.c dns.h
	./compile dns_class_equalb.c

dns_class_diff.o: \
compile dns_class_diff.c dns.h
	./compile dns_class_diff.c

dns_class_diffb.o: \
compile dns_class_diffb.c dns.h
	./compile dns_class_diffb.c

dns_class_zero.o: \
compile dns_class_zero.c dns.h
	./compile dns_class_zero.c

dns_d_empty.o: \
compile dns_d_empty.c dns.h
	./compile dns_d_empty.c

dns_d_ip4_localhost.o: \
compile dns_d_ip4_localhost.c dns.h
	./compile dns_d_ip4_localhost.c

dns_d_any_inaddr_arpa.o: \
compile dns_d_any_inaddr_arpa.c dns.h
	./compile dns_d_any_inaddr_arpa.c

dns_d_localhost_inaddr_arpa.o: \
compile dns_d_localhost_inaddr_arpa.c dns.h
	./compile dns_d_localhost_inaddr_arpa.c

dns_d_base_inaddr_arpa.o: \
compile dns_d_base_inaddr_arpa.c dns.h
	./compile dns_d_base_inaddr_arpa.c

dns_d_ip6_localhost.o: \
compile dns_d_ip6_localhost.c dns.h
	./compile dns_d_ip6_localhost.c

dns_d_ip6_localnet.o: \
compile dns_d_ip6_localnet.c dns.h
	./compile dns_d_ip6_localnet.c

dns_d_ip6_mcastprefix.o: \
compile dns_d_ip6_mcastprefix.c dns.h
	./compile dns_d_ip6_mcastprefix.c

dns_d_ip6_allnodes.o: \
compile dns_d_ip6_allnodes.c dns.h
	./compile dns_d_ip6_allnodes.c

dns_d_ip6_allrouters.o: \
compile dns_d_ip6_allrouters.c dns.h
	./compile dns_d_ip6_allrouters.c

dns_d_ip6_allhosts.o: \
compile dns_d_ip6_allhosts.c dns.h
	./compile dns_d_ip6_allhosts.c

dns_d_any_ip6_arpa.o: \
compile dns_d_any_ip6_arpa.c dns.h
	./compile dns_d_any_ip6_arpa.c

dns_d_localhost_ip6_arpa.o: \
compile dns_d_localhost_ip6_arpa.c dns.h
	./compile dns_d_localhost_ip6_arpa.c

dns_d_localnet_ip6_arpa.o: \
compile dns_d_localnet_ip6_arpa.c dns.h
	./compile dns_d_localnet_ip6_arpa.c

dns_d_mcastprefix_ip6_arpa.o: \
compile dns_d_mcastprefix_ip6_arpa.c dns.h
	./compile dns_d_mcastprefix_ip6_arpa.c

dns_d_allnodes_ip6_arpa.o: \
compile dns_d_allnodes_ip6_arpa.c dns.h
	./compile dns_d_allnodes_ip6_arpa.c

dns_d_allrouters_ip6_arpa.o: \
compile dns_d_allrouters_ip6_arpa.c dns.h
	./compile dns_d_allrouters_ip6_arpa.c

dns_d_allhosts_ip6_arpa.o: \
compile dns_d_allhosts_ip6_arpa.c dns.h
	./compile dns_d_allhosts_ip6_arpa.c

dns_d_base_ip6_arpa.o: \
compile dns_d_base_ip6_arpa.c dns.h
	./compile dns_d_base_ip6_arpa.c

dns_domain.3: \
sedit dns_domain.mdoc
	./sedit dns_domain.mdoc > dns_domain.3

dns_domain.0: \
mancat dns_domain.3
	./mancat dns_domain.3 > dns_domain.0

dns_domain_erase.o: \
compile dns_domain_erase.c dns.h
	./compile dns_domain_erase.c

dns_domain_active.o: \
compile dns_domain_active.c dns.h
	./compile dns_domain_active.c

dns_domain_catb.o: \
compile dns_domain_catb.c dns.h
	./compile dns_domain_catb.c

dns_domain_cat.o: \
compile dns_domain_cat.c dns.h
	./compile dns_domain_cat.c

dns_domain_cat.3: \
sedit dns_domain_cat.mdoc
	./sedit dns_domain_cat.mdoc > dns_domain_cat.3

dns_domain_cat.0: \
mancat dns_domain_cat.3
	./mancat dns_domain_cat.3 > dns_domain_cat.0

dns_domain_free.o: \
compile dns_domain_free.c dns.h
	./compile dns_domain_free.c

dns_domain_ready.o: \
compile dns_domain_ready.c dns.h
	./compile dns_domain_ready.c

dns_domain_fromdot.3: \
sedit dns_domain_fromdot.mdoc
	./sedit dns_domain_fromdot.mdoc > dns_domain_fromdot.3

dns_domain_fromdot.0: \
mancat dns_domain_fromdot.3
	./mancat dns_domain_fromdot.3 > dns_domain_fromdot.0

dns_domain_fromdot.o: \
compile dns_domain_fromdot.c dns.h
	./compile dns_domain_fromdot.c

dns_domain_length.3: \
sedit dns_domain_length.mdoc
	./sedit dns_domain_length.mdoc > dns_domain_length.3

dns_domain_length.0: \
mancat dns_domain_length.3
	./mancat dns_domain_length.3 > dns_domain_length.0

dns_domain_labellength.o: \
compile dns_domain_labellength.c dns.h
	./compile dns_domain_labellength.c

dns_domain_labelcount.o: \
compile dns_domain_labelcount.c dns.h
	./compile dns_domain_labelcount.c

dns_domain_labelparse.o: \
compile dns_domain_labelparse.c dns.h
	./compile dns_domain_labelparse.c

dns_domain_copyb.o: \
compile dns_domain_copyb.c dns.h
	./compile dns_domain_copyb.c

dns_domain_copy.o: \
compile dns_domain_copy.c dns.h
	./compile dns_domain_copy.c

dns_domain_copy.3: \
sedit dns_domain_copy.mdoc
	./sedit dns_domain_copy.mdoc > dns_domain_copy.3

dns_domain_copy.0: \
mancat dns_domain_copy.3
	./mancat dns_domain_copy.3 > dns_domain_copy.0

dns_domain_unpack.o: \
compile dns_domain_unpack.c dns.h
	./compile dns_domain_unpack.c

dns_domain_pack.o: \
compile dns_domain_pack.c dns.h
	./compile dns_domain_pack.c

dns_domain_lower.o: \
compile dns_domain_lower.c dns.h
	./compile dns_domain_lower.c

dns_domain_diff.3: \
sedit dns_domain_diff.mdoc
	./sedit dns_domain_diff.mdoc > dns_domain_diff.3

dns_domain_diff.0: \
mancat dns_domain_diff.3
	./mancat dns_domain_diff.3 > dns_domain_diff.0

dns_domain_diff.o: \
compile dns_domain_diff.c dns.h
	./compile dns_domain_diff.c

dns_domain_equal.o: \
compile dns_domain_equal.c dns.h
	./compile dns_domain_equal.c

dns_domain_equal.3: \
sedit dns_domain_equal.mdoc
	./sedit dns_domain_equal.mdoc > dns_domain_equal.3

dns_domain_equal.0: \
mancat dns_domain_equal.3
	./mancat dns_domain_equal.3 > dns_domain_equal.0

dns_domain_drop1label.o: \
compile dns_domain_drop1label.c dns.h
	./compile dns_domain_drop1label.c

dns_domain_suffix.o: \
compile dns_domain_suffix.c dns.h
	./compile dns_domain_suffix.c

dns_domain_ok.o: \
compile dns_domain_ok.c dns.h
	./compile dns_domain_ok.c

dns_domain_suffixpos.o: \
compile dns_domain_suffixpos.c dns.h
	./compile dns_domain_suffixpos.c

dns_domain_todot_cat.o: \
compile dns_domain_todot_cat.c dns.h
	./compile dns_domain_todot_cat.c

dns_id_unpack.o: \
compile dns_id_unpack.c dns.h
	./compile dns_id_unpack.c

dns_id_pack.o: \
compile dns_id_pack.c dns.h
	./compile dns_id_pack.c

dns_mx_packet.3: \
sedit dns_mx_packet.mdoc
	./sedit dns_mx_packet.mdoc > dns_mx_packet.3

dns_mx_packet.0: \
mancat dns_mx_packet.3
	./mancat dns_mx_packet.3 > dns_mx_packet.0

dns_mx_packet.o: \
compile dns_mx_packet.c dns.h
	./compile dns_mx_packet.c

dns_mx.3: \
sedit dns_mx.mdoc
	./sedit dns_mx.mdoc > dns_mx.3

dns_mx.0: \
mancat dns_mx.3
	./mancat dns_mx.3 > dns_mx.0

dns4_mx.o: \
compile dns4_mx.c dns.h
	./compile dns4_mx.c

dns6_mx.o: \
compile dns6_mx.c dns.h
	./compile dns6_mx.c

dns4_mxip4.o: \
compile dns4_mxip4.c dns.h
	./compile dns4_mxip4.c

dns6_mxip4.o: \
compile dns6_mxip4.c dns.h
	./compile dns6_mxip4.c

dns4_mxip6.o: \
compile dns4_mxip6.c dns.h
	./compile dns4_mxip6.c

dns6_mxip6.o: \
compile dns6_mxip6.c dns.h
	./compile dns6_mxip6.c

dns_name_packet.3: \
sedit dns_name_packet.mdoc
	./sedit dns_name_packet.mdoc > dns_name_packet.3

dns_name_packet.0: \
mancat dns_name_packet.3
	./mancat dns_name_packet.3 > dns_name_packet.0

dns_name_packet.o: \
compile dns_name_packet.c dns.h
	./compile dns_name_packet.c

dns_name4.3: \
sedit dns_name4.mdoc
	./sedit dns_name4.mdoc > dns_name4.3

dns_name4.0: \
mancat dns_name4.3
	./mancat dns_name4.3 > dns_name4.0

dns4_name4.o: \
compile dns4_name4.c dns.h
	./compile dns4_name4.c

dns6_name4.o: \
compile dns6_name4.c dns.h
	./compile dns6_name4.c

dns_name4_domain.o: \
compile dns_name4_domain.c dns.h die.h
	./compile dns_name4_domain.c

dns_name6.3: \
sedit dns_name6.mdoc
	./sedit dns_name6.mdoc > dns_name6.3

dns_name6.0: \
mancat dns_name6.3
	./mancat dns_name6.3 > dns_name6.0

dns4_name6.o: \
compile dns4_name6.c dns.h
	./compile dns4_name6.c

dns6_name6.o: \
compile dns6_name6.c dns.h
	./compile dns6_name6.c

dns_name6_domain.o: \
compile dns_name6_domain.c dns.h die.h
	./compile dns_name6_domain.c

dns4_notify.o: \
compile dns4_notify.c dns.h
	./compile dns4_notify.c

dns6_notify.o: \
compile dns6_notify.c dns.h
	./compile dns6_notify.c

dns_ns_packet.3: \
sedit dns_ns_packet.mdoc
	./sedit dns_ns_packet.mdoc > dns_ns_packet.3

dns_ns_packet.0: \
mancat dns_ns_packet.3
	./mancat dns_ns_packet.3 > dns_ns_packet.0

dns_ns_packet.o: \
compile dns_ns_packet.c dns.h
	./compile dns_ns_packet.c

dns_ns.3: \
sedit dns_ns.mdoc
	./sedit dns_ns.mdoc > dns_ns.3

dns_ns.0: \
mancat dns_ns.3
	./mancat dns_ns.3 > dns_ns.0

dns4_ns.o: \
compile dns4_ns.c dns.h
	./compile dns4_ns.c

dns6_ns.o: \
compile dns6_ns.c dns.h
	./compile dns6_ns.c

dns_packet.3: \
sedit dns_packet.mdoc
	./sedit dns_packet.mdoc > dns_packet.3

dns_packet.0: \
mancat dns_packet.3
	./mancat dns_packet.3 > dns_packet.0

dns_packet.o: \
compile dns_packet.c dns.h
	./compile dns_packet.c

dns_idna_encode.o: \
compile dns_idna_encode.c dns.h
	./compile dns_idna_encode.c

dns_random.3: \
sedit dns_random.mdoc
	./sedit dns_random.mdoc > dns_random.3

dns_random.0: \
mancat dns_random.3
	./mancat dns_random.3 > dns_random.0

dns_random.o: \
compile dns_random.c dns.h
	./compile dns_random.c

dns_rcip4.o: \
compile dns_rcip4.c dns.h
	./compile dns_rcip4.c

dns_rcip6.o: \
compile dns_rcip6.c dns.h
	./compile dns_rcip6.c

dns_rcode_str.o: \
compile dns_rcode_str.c dns.h
	./compile dns_rcode_str.c

dns_rcrw.o: \
compile dns_rcrw.c dns.h whitespace.h
	./compile dns_rcrw.c

dns4_resolve.o: \
compile dns4_resolve.c dns.h
	./compile dns4_resolve.c

dns6_resolve.o: \
compile dns6_resolve.c dns.h
	./compile dns6_resolve.c

dns_soa.3: \
sedit dns_soa.mdoc
	./sedit dns_soa.mdoc > dns_soa.3

dns_soa.0: \
mancat dns_soa.3
	./mancat dns_soa.3 > dns_soa.0

dns4_soa.o: \
compile dns4_soa.c dns.h
	./compile dns4_soa.c

dns6_soa.o: \
compile dns6_soa.c dns.h
	./compile dns6_soa.c

dns_soa_packet.3: \
sedit dns_soa_packet.mdoc
	./sedit dns_soa_packet.mdoc > dns_soa_packet.3

dns_soa_packet.0: \
mancat dns_soa_packet.3
	./mancat dns_soa_packet.3 > dns_soa_packet.0

dns_soa_packet.o: \
compile dns_soa_packet.c dns.h
	./compile dns_soa_packet.c

dns_sortip4.o: \
compile dns_sortip4.c dns.h
	./compile dns_sortip4.c

dns_sortip6.o: \
compile dns_sortip6.c dns.h
	./compile dns_sortip6.c

dns_spf.3: \
sedit dns_spf.mdoc
	./sedit dns_spf.mdoc > dns_spf.3

dns_spf.0: \
mancat dns_spf.3
	./mancat dns_spf.3 > dns_spf.0

dns4_spf.o: \
compile dns4_spf.c dns.h
	./compile dns4_spf.c

dns6_spf.o: \
compile dns6_spf.c dns.h
	./compile dns6_spf.c

dns4_transmit.3: \
sedit dns4_transmit.mdoc
	./sedit dns4_transmit.mdoc > dns4_transmit.3

dns4_transmit.0: \
mancat dns4_transmit.3
	./mancat dns4_transmit.3 > dns4_transmit.0

dns4_transmit.o: \
compile dns4_transmit.c dns.h dns4_transmit.h
	./compile dns4_transmit.c

dns4_transmit_start.o: \
compile dns4_transmit_start.c dns.h dns4_transmit.h
	./compile dns4_transmit_start.c

dns4_transmit_start_notify.o: \
compile dns4_transmit_start_notify.c dns.h dns4_transmit.h
	./compile dns4_transmit_start_notify.c

dns4_transmit_start_edns0.o: \
compile dns4_transmit_start_edns0.c dns.h dns4_transmit.h
	./compile dns4_transmit_start_edns0.c

dns6_transmit.3: \
sedit dns6_transmit.mdoc
	./sedit dns6_transmit.mdoc > dns6_transmit.3

dns6_transmit.0: \
mancat dns6_transmit.3
	./mancat dns6_transmit.3 > dns6_transmit.0

dns6_transmit.o: \
compile dns6_transmit.c dns.h dns6_transmit.h
	./compile dns6_transmit.c

dns6_transmit_start.o: \
compile dns6_transmit_start.c dns.h dns6_transmit.h
	./compile dns6_transmit_start.c

dns6_transmit_start_notify.o: \
compile dns6_transmit_start_notify.c dns.h dns6_transmit.h
	./compile dns6_transmit_start_notify.c

dns6_transmit_start_edns0.o: \
compile dns6_transmit_start_edns0.c dns.h dns6_transmit.h
	./compile dns6_transmit_start_edns0.c

dns_t_nil.o: \
compile dns_t_nil.c dns.h
	./compile dns_t_nil.c

dns_t_a.o: \
compile dns_t_a.c dns.h
	./compile dns_t_a.c

dns_t_ns.o: \
compile dns_t_ns.c dns.h
	./compile dns_t_ns.c

dns_t_cname.o: \
compile dns_t_cname.c dns.h
	./compile dns_t_cname.c

dns_t_soa.o: \
compile dns_t_soa.c dns.h
	./compile dns_t_soa.c

dns_t_ptr.o: \
compile dns_t_ptr.c dns.h
	./compile dns_t_ptr.c

dns_t_hinfo.o: \
compile dns_t_hinfo.c dns.h
	./compile dns_t_hinfo.c

dns_t_mx.o: \
compile dns_t_mx.c dns.h
	./compile dns_t_mx.c

dns_t_txt.o: \
compile dns_t_txt.c dns.h
	./compile dns_t_txt.c

dns_t_rp.o: \
compile dns_t_rp.c dns.h
	./compile dns_t_rp.c

dns_t_sig.o: \
compile dns_t_sig.c dns.h
	./compile dns_t_sig.c

dns_t_key.o: \
compile dns_t_key.c dns.h
	./compile dns_t_key.c

dns_t_aaaa.o: \
compile dns_t_aaaa.c dns.h
	./compile dns_t_aaaa.c

dns_t_loc.o: \
compile dns_t_loc.c dns.h
	./compile dns_t_loc.c

dns_t_srv.o: \
compile dns_t_srv.c dns.h
	./compile dns_t_srv.c

dns_t_naptr.o: \
compile dns_t_naptr.c dns.h
	./compile dns_t_naptr.c

dns_t_opt.o: \
compile dns_t_opt.c dns.h
	./compile dns_t_opt.c

dns_t_ds.o: \
compile dns_t_ds.c dns.h
	./compile dns_t_ds.c

dns_t_rrsig.o: \
compile dns_t_rrsig.c dns.h
	./compile dns_t_rrsig.c

dns_t_nsec.o: \
compile dns_t_nsec.c dns.h
	./compile dns_t_nsec.c

dns_t_dnskey.o: \
compile dns_t_dnskey.c dns.h
	./compile dns_t_dnskey.c

dns_t_spf.o: \
compile dns_t_spf.c dns.h
	./compile dns_t_spf.c

dns_t_ixfr.o: \
compile dns_t_ixfr.c dns.h
	./compile dns_t_ixfr.c

dns_t_axfr.o: \
compile dns_t_axfr.c dns.h
	./compile dns_t_axfr.c

dns_t_caa.o: \
compile dns_t_caa.c dns.h
	./compile dns_t_caa.c

dns_t_any.o: \
compile dns_t_any.c dns.h
	./compile dns_t_any.c

dns_type_copy.o: \
compile dns_type_copy.c dns.h
	./compile dns_type_copy.c

dns_type_unpack.o: \
compile dns_type_unpack.c dns.h
	./compile dns_type_unpack.c

dns_type_pack.o: \
compile dns_type_pack.c dns.h
	./compile dns_type_pack.c

dns_type_diff.o: \
compile dns_type_diff.c dns.h
	./compile dns_type_diff.c

dns_type_diffb.o: \
compile dns_type_diffb.c dns.h
	./compile dns_type_diffb.c

dns_type_equal.o: \
compile dns_type_equal.c dns.h
	./compile dns_type_equal.c

dns_type_equalb.o: \
compile dns_type_equalb.c dns.h
	./compile dns_type_equalb.c

dns_type_get.o: \
compile dns_type_get.c dns.h
	./compile dns_type_get.c

dns_type_set.o: \
compile dns_type_set.c dns.h
	./compile dns_type_set.c

dns_type_str.o: \
compile dns_type_str.c dns.h
	./compile dns_type_str.c

dns_type_zero.o: \
compile dns_type_zero.c dns.h
	./compile dns_type_zero.c

dns_txt_packet.3: \
sedit dns_txt_packet.mdoc
	./sedit dns_txt_packet.mdoc > dns_txt_packet.3

dns_txt_packet.0: \
mancat dns_txt_packet.3
	./mancat dns_txt_packet.3 > dns_txt_packet.0

dns_txt_packet.o: \
compile dns_txt_packet.c dns.h
	./compile dns_txt_packet.c

dns_txt.3: \
sedit dns_txt.mdoc
	./sedit dns_txt.mdoc > dns_txt.3

dns_txt.0: \
mancat dns_txt.3
	./mancat dns_txt.3 > dns_txt.0

dns4_txt.o: \
compile dns4_txt.c dns.h
	./compile dns4_txt.c

dns6_txt.o: \
compile dns6_txt.c dns.h
	./compile dns6_txt.c

dnscache.8: \
sedit dnscache.mdoc
	./sedit dnscache.mdoc > dnscache.8

dnscache.0: \
mancat dnscache.8
	./mancat dnscache.8 > dnscache.0

dnscache: \
load dnscache.o droproot.o okclient4.o ignore_ip_init.o log.a lame4.a \
cache.a query4.o dd4.o roots4.o packetquery.o udpclient4.o dd6.o tcpclient4.o \
client4.o client4_answer.o global_ip6.o global_ip4.o response.a safe.a \
dn_vector.o safe.a ioquery4.a die.a libdjbdns.a socket.lib debug.o
	./load dnscache udpclient4.o tcpclient4.o client4_answer.o client4.o \
	droproot.o okclient4.o query4.o roots4.o packetquery.o global_ip6.o \
	global_ip4.o dd6.o dd4.o response.a ioquery4.a cache.a dn_vector.o \
	lame4.a ignore_ip_init.o log.a debug.o safe.a die.a libdjbdns.a \
	`cat socket.lib`

dnscache.o: \
compile dnscache.c dns.h roots.h query.h query4.h response.h cache.h log.h \
client.h client4.h okclient.h droproot.h dnscache.h dn_vector.h \
ioquery4.h udpclient4.h tcpclient4.h die.h
	./compile dnscache.c

dnscache-conf.8: \
sedit dnscache-conf.mdoc
	./sedit dnscache-conf.mdoc > dnscache-conf.8

dnscache-conf.0: \
mancat dnscache-conf.8
	./mancat dnscache-conf.8 > dnscache-conf.0

dnscache-conf: \
load dnscache-conf.o generic-conf.o auto_prefix.o safe.a die.a
	./load dnscache-conf generic-conf.o auto_prefix.o die.a

dnscache-conf.o: \
compile dnscache-conf.c auto_prefix.h generic-conf.h die.h
	./compile dnscache-conf.c

dnscache-data.8: \
sedit dnscache-data.mdoc
	./sedit dnscache-data.mdoc > dnscache-data.8

dnscache-data.0: \
mancat dnscache-data.8
	./mancat dnscache-data.8 > dnscache-data.0

dnscache-data: \
load dnscache-data.o whitespace.o die.a libdjbdns.a
	./load dnscache-data whitespace.o die.a libdjbdns.a

dnscache-data.o: \
compile dnscache-data.c whitespace.h dns.h die.h
	./compile dnscache-data.c

dnscache-dnlist2data.8: \
sedit dnscache-dnlist2data.mdoc
	./sedit dnscache-dnlist2data.mdoc > dnscache-dnlist2data.8

dnscache-dnlist2data.0: \
mancat dnscache-dnlist2data.8
	./mancat dnscache-dnlist2data.8 > dnscache-dnlist2data.0

dnscache-dnlist2data: \
load dnscache-dnlist2data.o whitespace.o die.a libdjbdns.a
	./load dnscache-dnlist2data whitespace.o die.a libdjbdns.a

dnscache-dnlist2data.o: \
compile dnscache-dnlist2data.c whitespace.h dns.h die.h
	./compile dnscache-dnlist2data.c

dnscache-dnlist2roots.8: \
sedit dnscache-dnlist2roots.mdoc
	./sedit dnscache-dnlist2roots.mdoc > dnscache-dnlist2roots.8

dnscache-dnlist2roots.0: \
mancat dnscache-dnlist2roots.8
	./mancat dnscache-dnlist2roots.8 > dnscache-dnlist2roots.0

dnscache-dnlist2roots: \
load dnscache-dnlist2roots.o whitespace.o die.a libdjbdns.a
	./load dnscache-dnlist2roots whitespace.o die.a libdjbdns.a

dnscache-dnlist2roots.o: \
compile dnscache-dnlist2roots.c dns.h die.h whitespace.h
	./compile dnscache-dnlist2roots.c

dnscache-iplist2data.8: \
sedit dnscache-iplist2data.mdoc
	./sedit dnscache-iplist2data.mdoc > dnscache-iplist2data.8

dnscache-iplist2data.0: \
mancat dnscache-iplist2data.8
	./mancat dnscache-iplist2data.8 > dnscache-iplist2data.0

dnscache-iplist2data: \
load dnscache-iplist2data.o whitespace.o die.a libdjbdns.a
	./load dnscache-iplist2data whitespace.o die.a libdjbdns.a

dnscache-iplist2data.o: \
compile dnscache-iplist2data.c whitespace.h dns.h die.h
	./compile dnscache-iplist2data.c

dnscache6.8: \
sedit dnscache6.mdoc
	./sedit dnscache6.mdoc > dnscache6.8

dnscache6.0: \
mancat dnscache6.8
	./mancat dnscache6.8 > dnscache6.0

dnscache6: \
load dnscache6.o droproot.o ignore_ip_init.o okclient6.o log.a cache.a \
query6.o dd6.o roots6.o packetquery.o udpclient6.o dd4.o tcpclient6.o \
client6.o client6_answer.o global_ip6.o global_ip4.o safe.a dn_vector.o \
lame6.a response.a ioquery6.a safe.a die.a libdjbdns.a socket.lib debug.o
	./load dnscache6 udpclient6.o tcpclient6.o client6_answer.o client6.o \
	droproot.o okclient6.o query6.o packetquery.o global_ip6.o roots6.o \
	global_ip4.o dd6.o dd4.o response.a ioquery6.a cache.a dn_vector.o \
	ignore_ip_init.o lame6.a log.a debug.o safe.a die.a libdjbdns.a \
	`cat socket.lib`

dnscache6.o: \
compile dnscache6.c dns.h roots.h query.h query6.h response.h cache.h log.h \
client.h client6.h okclient.h droproot.h dnscache.h dn_vector.h \
ioquery6.h udpclient6.h tcpclient6.h die.h
	./compile dnscache6.c

dnscache6-conf.8: \
sedit dnscache6-conf.mdoc
	./sedit dnscache6-conf.mdoc > dnscache6-conf.8

dnscache6-conf.0: \
mancat dnscache6-conf.8
	./mancat dnscache6-conf.8 > dnscache6-conf.0

dnscache6-conf: \
load dnscache6-conf.o generic-conf.o auto_prefix.o safe.a die.a
	./load dnscache6-conf generic-conf.o auto_prefix.o die.a

dnscache6-conf.o: \
compile dnscache6-conf.c auto_prefix.h generic-conf.h die.h
	./compile dnscache6-conf.c

dnscache6-data.8: \
sedit dnscache6-data.mdoc
	./sedit dnscache6-data.mdoc > dnscache6-data.8

dnscache6-data.0: \
mancat dnscache6-data.8
	./mancat dnscache6-data.8 > dnscache6-data.0

dnscache6-data: \
load dnscache6-data.o whitespace.o die.a libdjbdns.a
	./load dnscache6-data whitespace.o die.a libdjbdns.a

dnscache6-data.o: \
compile dnscache6-data.c whitespace.h dns.h die.h
	./compile dnscache6-data.c

dnscache6-dnlist2data.8: \
sedit dnscache6-dnlist2data.mdoc
	./sedit dnscache6-dnlist2data.mdoc > dnscache6-dnlist2data.8

dnscache6-dnlist2data.0: \
mancat dnscache6-dnlist2data.8
	./mancat dnscache6-dnlist2data.8 > dnscache6-dnlist2data.0

dnscache6-dnlist2data: \
load dnscache6-dnlist2data.o whitespace.o die.a libdjbdns.a
	./load dnscache6-dnlist2data whitespace.o die.a libdjbdns.a

dnscache6-dnlist2data.o: \
compile dnscache6-dnlist2data.c whitespace.h dns.h die.h
	./compile dnscache6-dnlist2data.c

dnscache6-dnlist2roots.8: \
sedit dnscache6-dnlist2roots.mdoc
	./sedit dnscache6-dnlist2roots.mdoc > dnscache6-dnlist2roots.8

dnscache6-dnlist2roots.0: \
mancat dnscache6-dnlist2roots.8
	./mancat dnscache6-dnlist2roots.8 > dnscache6-dnlist2roots.0

dnscache6-dnlist2roots: \
load dnscache6-dnlist2roots.o whitespace.o die.a libdjbdns.a
	./load dnscache6-dnlist2roots whitespace.o die.a libdjbdns.a

dnscache6-dnlist2roots.o: \
compile dnscache6-dnlist2roots.c dns.h die.h
	./compile dnscache6-dnlist2roots.c

dnscache6-iplist2data.8: \
sedit dnscache6-iplist2data.mdoc
	./sedit dnscache6-iplist2data.mdoc > dnscache6-iplist2data.8

dnscache6-iplist2data.0: \
mancat dnscache6-iplist2data.8
	./mancat dnscache6-iplist2data.8 > dnscache6-iplist2data.0

dnscache6-iplist2data: \
load dnscache6-iplist2data.o whitespace.o die.a libdjbdns.a
	./load dnscache6-iplist2data whitespace.o die.a libdjbdns.a

dnscache6-iplist2data.o: \
compile dnscache6-iplist2data.c whitespace.h dns.h die.h
	./compile dnscache6-iplist2data.c

dnsfilter.1: \
sedit dnsfilter.mdoc
	./sedit dnsfilter.mdoc > dnsfilter.1

dnsfilter.0: \
mancat dnsfilter.1
	./mancat dnsfilter.1 > dnsfilter.0

dnsfilter: \
load dnsfilter.o die.a libdjbdns.a socket.lib
	./load dnsfilter die.a libdjbdns.a \
	`cat socket.lib`

dnsfilter.o: \
compile dnsfilter.c dns.h die.h
	./compile dnsfilter.c

dnsip.1: \
sedit dnsip.mdoc
	./sedit dnsip.mdoc > dnsip.1

dnsip.0: \
mancat dnsip.1
	./mancat dnsip.1 > dnsip.0

dnsip: \
load dnsip.o die.a libdjbdns.a socket.lib
	./load dnsip die.a libdjbdns.a \
	`cat socket.lib`

dnsip.o: \
compile dnsip.c dns.h die.h
	./compile dnsip.c

dnsip6.1: \
sedit dnsip6.mdoc
	./sedit dnsip6.mdoc > dnsip6.1

dnsip6.0: \
mancat dnsip6.1
	./mancat dnsip6.1 > dnsip6.0

dnsip6: \
load dnsip6.o die.a libdjbdns.a socket.lib
	./load dnsip6 die.a libdjbdns.a \
	`cat socket.lib`

dnsip6.o: \
compile dnsip6.c dns.h die.h
	./compile dnsip6.c

dnsipq.1: \
sedit dnsipq.mdoc
	./sedit dnsipq.mdoc > dnsipq.1

dnsipq.0: \
mancat dnsipq.1
	./mancat dnsipq.1 > dnsipq.0

dnsipq: \
load dnsipq.o die.a libdjbdns.a socket.lib
	./load dnsipq die.a libdjbdns.a \
	`cat socket.lib`

dnsipq.o: \
compile dnsipq.c dns.h die.h
	./compile dnsipq.c

dnsip6q.1: \
sedit dnsip6q.mdoc
	./sedit dnsip6q.mdoc > dnsip6q.1

dnsip6q.0: \
mancat dnsip6q.1
	./mancat dnsip6q.1 > dnsip6q.0

dnsip6q: \
load dnsip6q.o die.a libdjbdns.a socket.lib
	./load dnsip6q die.a libdjbdns.a \
	`cat socket.lib`

dnsip6q.o: \
compile dnsip6q.c dns.h die.h
	./compile dnsip6q.c

dnsmx.1: \
sedit dnsmx.mdoc
	./sedit dnsmx.mdoc > dnsmx.1

dnsmx.0: \
mancat dnsmx.1
	./mancat dnsmx.1 > dnsmx.0

dnsmx: \
load dnsmx.o die.a libdjbdns.a socket.lib
	./load dnsmx die.a libdjbdns.a \
	`cat socket.lib`

dnsmx.o: \
compile dnsmx.c dns.h die.h
	./compile dnsmx.c

dnsmxip.1: \
sedit dnsmxip.mdoc
	./sedit dnsmxip.mdoc > dnsmxip.1

dnsmxip.0: \
mancat dnsmxip.1
	./mancat dnsmxip.1 > dnsmxip.0

dnsmxip: \
load dnsmxip.o die.a libdjbdns.a socket.lib
	./load dnsmxip die.a libdjbdns.a \
	`cat socket.lib`

dnsmxip.o: \
compile dnsmxip.c dns.h die.h
	./compile dnsmxip.c

dnsmxip6.1: \
sedit dnsmxip6.mdoc
	./sedit dnsmxip6.mdoc > dnsmxip6.1

dnsmxip6.0: \
mancat dnsmxip6.1
	./mancat dnsmxip6.1 > dnsmxip6.0

dnsmxip6: \
load dnsmxip6.o die.a libdjbdns.a socket.lib
	./load dnsmxip6 die.a libdjbdns.a \
	`cat socket.lib`

dnsmxip6.o: \
compile dnsmxip6.c dns.h die.h
	./compile dnsmxip6.c

dnsname.1: \
sedit dnsname.mdoc
	./sedit dnsname.mdoc > dnsname.1

dnsname.0: \
mancat dnsname.1
	./mancat dnsname.1 > dnsname.0

dnsname: \
load dnsname.o die.a libdjbdns.a socket.lib
	./load dnsname die.a libdjbdns.a \
	`cat socket.lib`

dnsname.o: \
compile dnsname.c dns.h die.h
	./compile dnsname.c

dnsq.1: \
sedit dnsq.mdoc
	./sedit dnsq.mdoc > dnsq.1

dnsq.0: \
mancat dnsq.1
	./mancat dnsq.1 > dnsq.0

dnsq: \
load dnsq.o printrecord.o printpacket.o safe.a die.a libdjbdns.a socket.lib
	./load dnsq printrecord.o printpacket.o safe.a die.a libdjbdns.a \
	`cat socket.lib`

dnsq.o: \
compile dnsq.c dns.h printpacket.h die.h
	./compile dnsq.c

dnsqr.1: \
sedit dnsqr.mdoc
	./sedit dnsqr.mdoc > dnsqr.1

dnsqr.0: \
mancat dnsqr.1
	./mancat dnsqr.1 > dnsqr.0

dnsqr: \
load dnsqr.o printrecord.o printpacket.o safe.a die.a libdjbdns.a socket.lib
	./load dnsqr printrecord.o printpacket.o safe.a die.a libdjbdns.a \
	`cat socket.lib`

dnsqr.o: \
compile dnsqr.c printpacket.h dns.h die.h
	./compile dnsqr.c

dnsspf.1: \
sedit dnsspf.mdoc
	./sedit dnsspf.mdoc > dnsspf.1

dnsspf.0: \
mancat dnsspf.1
	./mancat dnsspf.1 > dnsspf.0

dnsspf: \
load dnsspf.o die.a libdjbdns.a socket.lib
	./load dnsspf die.a libdjbdns.a \
	`cat socket.lib`

dnsspf.o: \
compile dnsspf.c dns.h die.h
	./compile dnsspf.c

dnstrace.1: \
sedit dnstrace.mdoc
	./sedit dnstrace.mdoc > dnstrace.1

dnstrace.0: \
mancat dnstrace.1
	./mancat dnstrace.1 > dnstrace.0

dnstrace: \
load dnstrace.o dd6.o dd4.o printrecord.o address4_vector.o address6_vector.o \
ns_vector.o query_vector.o qt_vector.o safe.a die.a libdjbdns.a socket.lib
	./load dnstrace dd6.o dd4.o printrecord.o address4_vector.o \
	address6_vector.o ns_vector.o query_vector.o qt_vector.o safe.a die.a \
	libdjbdns.a \
	`cat socket.lib`

dnstrace.o: \
compile dnstrace.c printrecord.h dd.h dns.h address4_vector.h \
address6_vector.h die.h safe.h ns_vector.h query_vector.h qt_vector.h
	./compile dnstrace.c

dnstrace6.1: \
sedit dnstrace6.mdoc
	./sedit dnstrace6.mdoc > dnstrace6.1

dnstrace6.0: \
mancat dnstrace6.1
	./mancat dnstrace6.1 > dnstrace6.0

dnstrace6: \
load dnstrace6.o dd6.o dd4.o printrecord.o address4_vector.o \
address6_vector.o ns_vector.o query_vector.o qt_vector.o safe.a die.a \
libdjbdns.a socket.lib
	./load dnstrace6 dd6.o dd4.o printrecord.o address4_vector.o \
	address6_vector.o ns_vector.o query_vector.o qt_vector.o safe.a die.a \
	libdjbdns.a \
	`cat socket.lib`

dnstrace6.o: \
compile dnstrace6.c printrecord.h dd.h dns.h address4_vector.h \
address6_vector.h die.h safe.h ns_vector.h query_vector.h qt_vector.h
	./compile dnstrace6.c

dnstracesort.1: \
sedit dnstracesort.mdoc
	./sedit dnstracesort.mdoc > dnstracesort.1

dnstracesort.0: \
mancat dnstracesort.1
	./mancat dnstracesort.1 > dnstracesort.0

dnstracesort: \
sedit warn-auto.sh dnstracesort.sh
	cat warn-auto.sh > dnstracesort
	./sedit dnstracesort.sh >> dnstracesort
	chmod 755 dnstracesort

dnstxt.1: \
sedit dnstxt.mdoc
	./sedit dnstxt.mdoc > dnstxt.1

dnstxt.0: \
mancat dnstxt.1
	./mancat dnstxt.1 > dnstxt.0

dnstxt: \
load dnstxt.o die.a libdjbdns.a socket.lib
	./load dnstxt die.a libdjbdns.a \
	`cat socket.lib`

dnstxt.o: \
compile dnstxt.c dns.h die.h
	./compile dnstxt.c

droproot.o: \
compile droproot.c droproot.h die.h
	./compile droproot.c

generic-conf.o: \
compile generic-conf.c generic-conf.h die.h
	./compile generic-conf.c

global_ip4.o: \
compile global_ip4.c dnscache.h dns.h dd.h
	./compile global_ip4.c

global_ip6.o: \
compile global_ip6.c dnscache.h dns.h
	./compile global_ip6.c

hier.o: \
compile hier.c auto_prefix.h
	./compile hier.c

ignore_ip_init.o: \
compile ignore_ip_init.c ignore_ip_init.h
	./compile ignore_ip_init.c

install: \
load install.o hier.o auto_prefix.o safe.a die.a
	./load install hier.o auto_prefix.o -ldjbinstall

install.o: \
compile install.c
	./compile install.c

instcheck: \
load instcheck.o hier.o auto_prefix.o safe.a die.a
	./load instcheck hier.o auto_prefix.o -ldjbinstcheck

instcheck.o: \
compile instcheck.c
	./compile instcheck.c

ioquery4.a: \
makelib ioquery4.o ioquery4_havepacket.o ioquery_havepacket.o
	./makelib ioquery4.a ioquery4.o ioquery4_havepacket.o \
	ioquery_havepacket.o

ioquery6.a: \
makelib ioquery6.o ioquery6_havepacket.o ioquery_havepacket.o
	./makelib ioquery6.a ioquery6.o ioquery6_havepacket.o \
	ioquery_havepacket.o

ioquery_havepacket.o: \
compile ioquery_havepacket.c ioquery_havepacket.h dns.h die.h safe.h cache.h
	./compile ioquery_havepacket.c

ioquery4.o: \
compile ioquery4.c ioquery4.h dns.h log.h dnscache.h dn_vector.h \
query.h query4.h die.h tcpclient4.h udpclient4.h cache.h ioquery.c
	./compile ioquery4.c

ioquery4_havepacket.o: \
compile ioquery4_havepacket.c ioquery_havepacket.h ioquery4.h dns.h \
log.h dnscache.h dn_vector.h cache.h query.h query4.h client.h client4.h \
tcpclient4.h die.h safe.h udpclient4.h lame4_servers.h
	./compile ioquery4_havepacket.c

ioquery6.o: \
compile ioquery6.c ioquery6.h dns.h log.h dnscache.h dn_vector.h \
die.h query.h query6.h tcpclient6.h udpclient6.h cache.h ioquery.c
	./compile ioquery6.c

ioquery6_havepacket.o: \
compile ioquery6_havepacket.c ioquery_havepacket.h ioquery6.h dns.h \
log.h dnscache.h die.h dn_vector.h cache.h query.h query6.h client.h \
client6.h tcpclient6.h safe.h udpclient6.h lame6_servers.h
	./compile ioquery6_havepacket.c

libs: \
libdjbdns.a

log.a: \
makelib log6_tx.o log6_tcpopen.o log6_drop_query.o \
log6_tcpclose.o log6_rcode.o log6_rr.o log6_rr_soa.o log6_rr_ptr.o \
log6_rr_ns.o log6_rr_mx.o log6_rr_cname.o log6_rr_aaaa.o log6_rr_a.o \
log6_rejected_source_ip.o log6_rejected_packet.o log6_query.o \
log6_query_done.o log6_nodata.o log6_lame.o \
log6_ignore_referral.o log4_tx.o log4_tcpopen.o log4_tcpclose.o \
log4_rcode.o log4_rr.o log4_rr_soa.o log4_rr_ptr.o log4_rr_ns.o \
log4_rr_mx.o log4_rr_cname.o log4_rr_aaaa.o log4_rr_a.o \
log4_rejected_source_ip.o log4_rejected_packet.o log4_query.o \
log4_query_done.o log4_nodata.o log4_ignore_referral.o \
log4_lame.o log_stats.o log_ip6_bracket.o log.o log_glueless_a.o \
log_glueless_aaaa.o log6_ip_ttl_type_name.o log4_ip_ttl_type_name.o \
log4_drop_query.o
	./makelib log.a log6_tx.o log6_tcpopen.o log6_tcpclose.o \
	log6_rcode.o log6_rr.o log6_rr_soa.o log6_rr_ptr.o log6_rr_ns.o \
	log6_rr_mx.o log6_rr_cname.o log6_rr_aaaa.o log6_rr_a.o \
	log6_rejected_source_ip.o log6_rejected_packet.o log6_query.o \
	log6_query_done.o log6_nodata.o log6_lame.o \
	log6_ignore_referral.o log6_drop_query.o log4_drop_query.o log4_tx.o \
	log4_tcpopen.o log4_tcpclose.o \
	log4_rcode.o log4_rr.o log4_rr_soa.o log4_rr_ptr.o log4_rr_ns.o \
	log4_rr_mx.o log4_rr_cname.o log4_rr_aaaa.o log4_rr_a.o \
	log4_rejected_source_ip.o log4_rejected_packet.o log4_query.o \
	log4_query_done.o log4_nodata.o \
	log4_ignore_referral.o log4_lame.o log_glueless_aaaa.o \
	log_glueless_a.o log_stats.o log_ip6_bracket.o \
	log6_ip_ttl_type_name.o log4_ip_ttl_type_name.o log.o

log.o: \
compile log.c log.h dns.h
	./compile log.c

log_glueless_a.o: \
compile log_glueless_a.c log.h dns.h
	./compile log_glueless_a.c

log_glueless_aaaa.o: \
compile log_glueless_aaaa.c log.h dns.h
	./compile log_glueless_aaaa.c

log_stats.o: \
compile log_stats.c log.h dns.h
	./compile log_stats.c

log_ip6_bracket.o: \
compile log_ip6_bracket.c log.h dns.h
	./compile log_ip6_bracket.c

log4_drop_query.o: \
compile log4_drop_query.c log.h dns.h
	./compile log4_drop_query.c

log4_ignore_referral.o: \
compile log4_ignore_referral.c log.h dns.h
	./compile log4_ignore_referral.c

log4_ip_ttl_type_name.o: \
compile log4_ip_ttl_type_name.c log.h dns.h
	./compile log4_ip_ttl_type_name.c

log4_lame.o: \
compile log4_lame.c log.h dns.h lame4_servers.h
	./compile log4_lame.c

log4_nodata.o: \
compile log4_nodata.c log.h dns.h
	./compile log4_nodata.c

log4_query_done.o: \
compile log4_query_done.c log.h dns.h
	./compile log4_query_done.c

log4_query.o: \
compile log4_query.c log.h dns.h
	./compile log4_query.c

log4_rejected_packet.o: \
compile log4_rejected_packet.c log.h dns.h
	./compile log4_rejected_packet.c

log4_rejected_source_ip.o: \
compile log4_rejected_source_ip.c log.h dns.h
	./compile log4_rejected_source_ip.c

log4_rr_a.o: \
compile log4_rr_a.c log.h dns.h
	./compile log4_rr_a.c

log4_rr_aaaa.o: \
compile log4_rr_aaaa.c log.h dns.h
	./compile log4_rr_aaaa.c

log4_rr_cname.o: \
compile log4_rr_cname.c log.h dns.h
	./compile log4_rr_cname.c

log4_rr_mx.o: \
compile log4_rr_mx.c log.h dns.h
	./compile log4_rr_mx.c

log4_rr_ns.o: \
compile log4_rr_ns.c log.h dns.h
	./compile log4_rr_ns.c

log4_rr_ptr.o: \
compile log4_rr_ptr.c log.h dns.h
	./compile log4_rr_ptr.c

log4_rr_soa.o: \
compile log4_rr_soa.c log.h dns.h
	./compile log4_rr_soa.c

log4_rr.o: \
compile log4_rr.c log.h dns.h
	./compile log4_rr.c

log4_rcode.o: \
compile log4_rcode.c log.h dns.h
	./compile log4_rcode.c

log4_tcpclose.o: \
compile log4_tcpclose.c log.h dns.h
	./compile log4_tcpclose.c

log4_tcpopen.o: \
compile log4_tcpopen.c log.h dns.h
	./compile log4_tcpopen.c

log4_tx.o: \
compile log4_tx.c log.h dns.h
	./compile log4_tx.c

log6_drop_query.o: \
compile log6_drop_query.c log.h dns.h
	./compile log6_drop_query.c

log6_ignore_referral.o: \
compile log6_ignore_referral.c log.h dns.h
	./compile log6_ignore_referral.c

log6_ip_ttl_type_name.o: \
compile log6_ip_ttl_type_name.c log.h dns.h
	./compile log6_ip_ttl_type_name.c

log6_lame.o: \
compile log6_lame.c log.h dns.h lame6_servers.h
	./compile log6_lame.c

log6_nodata.o: \
compile log6_nodata.c log.h dns.h
	./compile log6_nodata.c

log6_query_done.o: \
compile log6_query_done.c log.h dns.h
	./compile log6_query_done.c

log6_query.o: \
compile log6_query.c log.h dns.h
	./compile log6_query.c

log6_rejected_packet.o: \
compile log6_rejected_packet.c log.h dns.h
	./compile log6_rejected_packet.c

log6_rejected_source_ip.o: \
compile log6_rejected_source_ip.c log.h dns.h
	./compile log6_rejected_source_ip.c

log6_rr_a.o: \
compile log6_rr_a.c log.h dns.h
	./compile log6_rr_a.c

log6_rr_aaaa.o: \
compile log6_rr_aaaa.c log.h dns.h
	./compile log6_rr_aaaa.c

log6_rr_cname.o: \
compile log6_rr_cname.c log.h dns.h
	./compile log6_rr_cname.c

log6_rr_mx.o: \
compile log6_rr_mx.c log.h dns.h
	./compile log6_rr_mx.c

log6_rr_ns.o: \
compile log6_rr_ns.c log.h dns.h
	./compile log6_rr_ns.c

log6_rr_ptr.o: \
compile log6_rr_ptr.c log.h dns.h
	./compile log6_rr_ptr.c

log6_rr_soa.o: \
compile log6_rr_soa.c log.h dns.h
	./compile log6_rr_soa.c

log6_rr.o: \
compile log6_rr.c log.h dns.h
	./compile log6_rr.c

log6_rcode.o: \
compile log6_rcode.c log.h dns.h
	./compile log6_rcode.c

log6_tcpclose.o: \
compile log6_tcpclose.c log.h dns.h
	./compile log6_tcpclose.c

log6_tcpopen.o: \
compile log6_tcpopen.c log.h dns.h
	./compile log6_tcpopen.c

log6_tx.o: \
compile log6_tx.c log.h dns.h
	./compile log6_tx.c

lame4.a: \
makelib lame4_servers.o lame4_vector.o
	./makelib lame4.a lame4_servers.o lame4_vector.o

lame4_servers.o: \
compile lame4_servers.c lame4_servers.h lame4_vector.h dns.h die.h
	./compile lame4_servers.c

lame4_vector.o: \
compile lame4_vector.c lame4_vector.h dns.h
	./compile lame4_vector.c

lame6.a: \
makelib lame6_servers.o lame6_vector.o
	./makelib lame6.a lame6_servers.o lame6_vector.o

lame6_servers.o: \
compile lame6_servers.c lame6_servers.h lame6_vector.h dns.h die.h
	./compile lame6_servers.c

lame6_vector.o: \
compile lame6_vector.c lame6_vector.h dns.h
	./compile lame6_vector.c

macro_rbldns6_max_mask.h: \
conf-rbldns6-max-mask
	rm -f macro_rbldns6_max_mask.h
	c-auto-define "RBLDNS6_MAX_MASK" "`head -n 1 conf-rbldns6-max-mask`" \
	> macro_rbldns6_max_mask.h

makelib: \
print-ar.sh warn-auto.sh conf-ar
	rm -f makelib
	sh print-ar.sh > makelib
	chmod 700 makelib

man: \
djbdns.0 dnsfilter.0 qualification.0 dnstracesort.0 dblcheck.0 rblcheck.0 \
rblcheck6.0 dnsip.0 dnsip6.0 dnsipq.0 dnsip6q.0 dnsmxip.0 dnsmxip6.0 \
dnstrace.0 dnstrace6.0 dnsmx.0 dnsname.0 dnsq.0 dnsqr.0 dnstxt.0 dnsspf.0 \
tinydns.0 tinydns6.0 tinydns-conf.0 tinydns6-conf.0 tinydns-data.0 \
tinydns-get.0 tinydns-edit.0 tinydns-bind2data.0 \
axfrdns.0 axfrdns6.0 axfrdns-conf.0 axfrdns6-conf.0 axfr-get.0 axfr-notify.0 \
dnscache.0 dnscache-conf.0 dnscache-data.0 tinydns-v1data2data.0 \
dnscache-iplist2data.0 dnscache-dnlist2data.0 tinydns-v3data2data.0 \
dnscache6.0 dnscache6-conf.0 dnscache6-data.0 tinydns-dnlist2data.0 \
dnscache6-iplist2data.0 dnscache6-dnlist2data.0 \
rbldns.0 rbldns6.0 rbldns-conf.0 rbldns6-conf.0 rbldns-data.0 rbldns6-data.0 \
dbldns.0 dbldns6.0 dbldns-conf.0 dbldns6-conf.0 dbldns-data.0 \
walldns.0 walldns6.0 walldns-conf.0 walldns6-conf.0 \
wilddns.0 wilddns6.0 wilddns-conf.0 wilddns6-conf.0 wilddns-data.0 \
dns_domain.0 dns_domain_equal.0 dns_domain_copy.0 dns_domain_length.0 \
dns_domain_fromdot.0 dns_ip6_qualify.0 dns_ip4_qualify.0 dns6_transmit.0 \
dns4_transmit.0 dns_ip6.0 dns_ip4.0 dns_name_packet.0 dns_txt_packet.0 \
dns_packet.0 dns_random.0 dns_name4.0 dns_name6.0 dns_txt.0 dns_mx.0 \
dblcheck6.0 dns_spf.0 dns_mx_packet.0 dns_ip4_packet.0 dns_ip6_packet.0 \
dns_soa_packet.0 dns_soa.0 dns_ns.0 dns_ns_packet.0 dns_domain_cat.0 \
dns_domain_diff.0

sedit: \
print-sedit.sh warn-auto.sh VERSION DATE conf-prefix
	rm -f sedit
	sh print-sedit.sh > sedit
	chmod 700 sedit

mancat: \
print-mancat.sh warn-auto.sh
	rm -f mancat
	sh print-mancat.sh > mancat
	chmod 700 mancat

mxip_data_diff46.o: \
compile mxip_data_diff46.c dns.h
	./compile mxip_data_diff46.c

mxip_data_diff64.o: \
compile mxip_data_diff64.c dns.h
	./compile mxip_data_diff64.c

mxip_vector_append4.o: \
compile mxip_vector_append4.c dns.h
	./compile mxip_vector_append4.c

mxip_vector_append6.o: \
compile mxip_vector_append6.c dns.h
	./compile mxip_vector_append6.c

mxip_vector_cat4.o: \
compile mxip_vector_cat4.c dns.h
	./compile mxip_vector_cat4.c

mxip_vector_cat6.o: \
compile mxip_vector_cat6.c dns.h
	./compile mxip_vector_cat6.c

mxip_vector_ready.o: \
compile mxip_vector_ready.c dns.h
	./compile mxip_vector_ready.c

mxip_vector_sort46.o: \
compile mxip_vector_sort46.c dns.h
	./compile mxip_vector_sort46.c

mxip_vector_sort64.o: \
compile mxip_vector_sort64.c dns.h
	./compile mxip_vector_sort64.c

mxip_vector_swap.o: \
compile mxip_vector_swap.c dns.h
	./compile mxip_vector_swap.c

mxip4_data_diff.o: \
compile mxip4_data_diff.c dns.h
	./compile mxip4_data_diff.c

mxip4_vector_append.o: \
compile mxip4_vector_append.c dns.h
	./compile mxip4_vector_append.c

mxip4_vector_erase.o: \
compile mxip4_vector_erase.c dns.h
	./compile mxip4_vector_erase.c

mxip4_vector_ready.o: \
compile mxip4_vector_ready.c dns.h
	./compile mxip4_vector_ready.c

mxip4_vector_sort.o: \
compile mxip4_vector_sort.c dns.h
	./compile mxip4_vector_sort.c

mxip4_vector_swap.o: \
compile mxip4_vector_swap.c dns.h
	./compile mxip4_vector_swap.c

mxip6_data_diff.o: \
compile mxip6_data_diff.c dns.h
	./compile mxip6_data_diff.c

mxip6_vector_append.o: \
compile mxip6_vector_append.c dns.h
	./compile mxip6_vector_append.c

mxip6_vector_erase.o: \
compile mxip6_vector_erase.c dns.h
	./compile mxip6_vector_erase.c

mxip6_vector_ready.o: \
compile mxip6_vector_ready.c dns.h
	./compile mxip6_vector_ready.c

mxip6_vector_sort.o: \
compile mxip6_vector_sort.c dns.h
	./compile mxip6_vector_sort.c

mxip6_vector_swap.o: \
compile mxip6_vector_swap.c dns.h
	./compile mxip6_vector_swap.c

mxname_data_diff.o: \
compile mxname_data_diff.c dns.h
	./compile mxname_data_diff.c

mxname_vector_append.o: \
compile mxname_vector_append.c dns.h
	./compile mxname_vector_append.c

mxname_vector_erase.o: \
compile mxname_vector_erase.c dns.h
	./compile mxname_vector_erase.c

mxname_vector_ready.o: \
compile mxname_vector_ready.c dns.h
	./compile mxname_vector_ready.c

mxname_vector_remove.o: \
compile mxname_vector_remove.c dns.h
	./compile mxname_vector_remove.c

mxname_vector_sort.o: \
compile mxname_vector_sort.c dns.h
	./compile mxname_vector_sort.c

mxname_vector_swap.o: \
compile mxname_vector_swap.c dns.h
	./compile mxname_vector_swap.c

ns_vector.o: \
compile ns_vector.c dns.h ns_vector.h
	./compile ns_vector.c

okclient4.o: \
compile okclient4.c okclient.h
	./compile okclient4.c

okclient6.o: \
compile okclient6.c okclient.h
	./compile okclient6.c

packetquery.o: \
compile packetquery.c dnscache.h dns.h safe.h
	./compile packetquery.c

dns_type_parse.o: \
compile dns_type_parse.c dns.h
	./compile dns_type_parse.c

printpacket.o: \
compile printpacket.c dns.h printrecord.h printpacket.h safe.h
	./compile printpacket.c

printrecord.o: \
compile printrecord.c dns.h printrecord.h safe.h
	./compile printrecord.c

prog: \
dnsip dnsip6 dnsipq dnsip6q dnstrace dnstrace6 dnsmxip dnsmxip6 dnsname \
dnstxt dnsmx dnsqr dnsq dnsspf dnstracesort dnsfilter rts cachetest utime \
random-ip rblcheck rblcheck6 dblcheck dblcheck6 axfr-get axfr-notify axfrdns \
axfrdns-conf axfrdns6 axfrdns6-conf dbldns-data dbldns dbldns-conf dbldns6 \
dbldns6-conf dnscache dnscache-conf dnscache-data dnscache-dnlist2data \
dnscache-iplist2data dnscache6 dnscache6-conf dnscache6-data \
dnscache6-dnlist2data dnscache6-iplist2data rbldns rbldns-conf rbldns-data \
rbldns6 rbldns6-conf rbldns6-data tinydns-data tinydns-get tinydns-edit \
tinydns-bind2data tinydns tinydns-conf tinydns6 tinydns6-conf walldns \
walldns-conf walldns6 walldns6-conf wilddns-data wilddns wilddns-conf \
wilddns6 wilddns6-conf test_domain_constants test_domain_name_decode install \
instcheck rbl tinydns-v3data2data tinydns-v1data2data tinydns-dnlist2data \
dnscache-dnlist2roots dnscache6-dnlist2roots test_idna

qualification.5: \
sedit qualification.mdoc
	./sedit qualification.mdoc > qualification.5

qualification.0: \
mancat qualification.5
	./mancat qualification.5 > qualification.0

qlog.o: \
compile qlog.c qlog.h dns.h
	./compile qlog.c

qlog4.o: \
compile qlog4.c qlog.h dns.h
	./compile qlog4.c

qlog6.o: \
compile qlog6.c qlog.h dns.h
	./compile qlog6.c

qt_vector.o: \
compile qt_vector.c dns.h qt_vector.h
	./compile qt_vector.c

query4.o: \
compile query4.c roots.h log.h cache.h dns.h dd.h response.h query.h query4.h \
die.h dnscache.h dn_vector.h ioquery4.h tcpclient4.h udpclient4.h \
query.c lame4_servers.h
	./compile query4.c

query6.o: \
compile query6.c roots.h log.h cache.h dns.h dd.h response.h query.h query6.h \
die.h dnscache.h dn_vector.h ioquery6.h tcpclient6.h udpclient6.h \
query.c lame6_servers.h
	./compile query6.c

query_vector.o: \
compile query_vector.c dns.h query_vector.h
	./compile query_vector.c

random-ip: \
load random-ip.o libdjbdns.a
	./load random-ip libdjbdns.a

random-ip.o: \
compile random-ip.c dns.h
	./compile random-ip.c

rbl: \
sedit warn-auto.sh rbl.sh
	( cat warn-auto.sh && ./sedit rbl.sh ) > rbl
	chmod 755 rbl

rblcheck.1: \
sedit rblcheck.mdoc
	./sedit rblcheck.mdoc > rblcheck.1

rblcheck.0: \
mancat rblcheck.1
	./mancat rblcheck.1 > rblcheck.0

rblcheck: \
load rblcheck.o die.a libdjbdns.a socket.lib
	./load rblcheck die.a libdjbdns.a `cat socket.lib`

rblcheck.o: \
compile rblcheck.c dns.h die.h
	./compile rblcheck.c

rblcheck6.1: \
sedit rblcheck6.mdoc
	./sedit rblcheck6.mdoc > rblcheck6.1

rblcheck6.0: \
mancat rblcheck6.1
	./mancat rblcheck6.1 > rblcheck6.0

rblcheck6: \
load rblcheck6.o die.a libdjbdns.a socket.lib
	./load rblcheck6 die.a libdjbdns.a `cat socket.lib`

rblcheck6.o: \
compile rblcheck6.c dns.h die.h
	./compile rblcheck6.c

rbldns.8: \
sedit rbldns.mdoc
	./sedit rbldns.mdoc > rbldns.8

rbldns.0: \
mancat rbldns.8
	./mancat rbldns.8 > rbldns.0

rbldns: \
load rbldns.o server4.o dd4.o droproot.o qlog4.o qlog.o rbllookup.o \
data_cdb.o response.a safe.a die.a libdjbdns.a socket.lib
	./load rbldns rbllookup.o data_cdb.o server4.o dd4.o droproot.o \
	qlog4.o qlog.o response.a safe.a die.a libdjbdns.a \
	`cat socket.lib`

rbldns.o: \
compile rbldns.c rbllookup.h data_cdb.h dns.h dd.h response.h respond.h
	./compile rbldns.c

rbldns-conf.8: \
sedit rbldns-conf.mdoc
	./sedit rbldns-conf.mdoc > rbldns-conf.8

rbldns-conf.0: \
mancat rbldns-conf.8
	./mancat rbldns-conf.8 > rbldns-conf.0

rbldns-conf: \
load rbldns-conf.o generic-conf.o auto_prefix.o die.a
	./load rbldns-conf generic-conf.o auto_prefix.o die.a

rbldns-conf.o: \
compile rbldns-conf.c auto_prefix.h generic-conf.h die.h
	./compile rbldns-conf.c

rbldns-data.8: \
sedit rbldns-data.mdoc
	./sedit rbldns-data.mdoc > rbldns-data.8

rbldns-data.0: \
mancat rbldns-data.8
	./mancat rbldns-data.8 > rbldns-data.0

rbldns-data: \
load rbldns-data.o whitespace.o die.a
	./load rbldns-data whitespace.o die.a

rbldns-data.o: \
compile rbldns-data.c whitespace.h dns.h die.h
	./compile rbldns-data.c

rbldns6.8: \
sedit rbldns6.mdoc
	./sedit rbldns6.mdoc > rbldns6.8

rbldns6.0: \
mancat rbldns6.8
	./mancat rbldns6.8 > rbldns6.0

rbldns6: \
load rbldns6.o server6.o dd6.o droproot.o qlog6.o qlog.o rbllookup.o \
data_cdb.o response.a safe.a die.a libdjbdns.a socket.lib
	./load rbldns6 rbllookup.o data_cdb.o server6.o dd6.o droproot.o \
	qlog6.o qlog.o response.a safe.a die.a libdjbdns.a \
	`cat socket.lib`

rbldns6.o: \
compile rbldns6.c rbllookup.h data_cdb.h dns.h dd.h response.h respond.h rbldns6.h \
macro_rbldns6_max_mask.h
	./compile rbldns6.c

rbldns6-conf.8: \
sedit rbldns6-conf.mdoc
	./sedit rbldns6-conf.mdoc > rbldns6-conf.8

rbldns6-conf.0: \
mancat rbldns6-conf.8
	./mancat rbldns6-conf.8 > rbldns6-conf.0

rbldns6-conf: \
load rbldns6-conf.o generic-conf.o auto_prefix.o die.a
	./load rbldns6-conf generic-conf.o auto_prefix.o die.a

rbldns6-conf.o: \
compile rbldns6-conf.c auto_prefix.h generic-conf.h die.h
	./compile rbldns6-conf.c

rbldns6-data.8: \
sedit rbldns6-data.mdoc
	./sedit rbldns6-data.mdoc > rbldns6-data.8

rbldns6-data.0: \
mancat rbldns6-data.8
	./mancat rbldns6-data.8 > rbldns6-data.0

rbldns6-data: \
load rbldns6-data.o whitespace.o die.a
	./load rbldns6-data whitespace.o die.a

rbldns6-data.o: \
compile rbldns6-data.c whitespace.h dns.h die.h rbldns6.h \
macro_rbldns6_max_mask.h
	./compile rbldns6-data.c

rbllookup.o: \
compile rbllookup.c rbllookup.h data_cdb.h dns.h response.h respond.h die.h
	./compile rbllookup.c

response.a: \
makelib response_send6.o response_send4.o response_addclass.o \
response_addip4_r.o response_addip4.o response_addip6_r.o response_addip6.o \
response_addtype.o response_cname.o response.o
	./makelib response.a response_send6.o response_send4.o \
	response_addclass.o response_addip4_r.o response_addip4.o \
	response_addip6_r.o response_addip6.o response_addtype.o \
	response_cname.o response.o

response.o: \
compile response.c dnscache.h response.h die.h dns.h
	./compile response.c

response_addclass.o: \
compile response_addclass.c response.h dns.h
	./compile response_addclass.c

response_addip4_r.o: \
compile response_addip4_r.c response.h dns.h
	./compile response_addip4_r.c

response_addip4.o: \
compile response_addip4.c response.h dns.h
	./compile response_addip4.c

response_addip6_r.o: \
compile response_addip6_r.c response.h dns.h
	./compile response_addip6_r.c

response_addip6.o: \
compile response_addip6.c response.h dns.h
	./compile response_addip6.c

response_addtype.o: \
compile response_addtype.c response.h dns.h
	./compile response_addtype.c

response_send4.o: \
compile response_send4.c response.h dns.h
	./compile response_send4.c

response_send6.o: \
compile response_send6.c response.h dns.h
	./compile response_send6.c

response_cname.o: \
compile response_cname.c response.h dns.h
	./compile response_cname.c

roots4.o: \
compile roots4.c dnscache.h roots.h die.h dns.h
	./compile roots4.c

roots6.o: \
compile roots6.c dnscache.h roots.h die.h dns.h
	./compile roots6.c

rts: \
warn-auto.sh rts.sh sedit
	( cat warn-auto.sh && ./sedit rts.sh ) > rts
	chmod 755 rts

safe.a: \
makelib safe_packet_getname.o
	./makelib safe.a safe_packet_getname.o

safe_packet_getname.o: \
compile safe_packet_getname.c dns.h die.h safe.h
	./compile safe_packet_getname.c

server4.o: \
compile server4.c droproot.h qlog.h response.h dns.h die.h safe.h respond.h
	./compile server4.c

server6.o: \
compile server6.c droproot.h qlog.h response.h dns.h die.h safe.h respond.h
	./compile server6.c

soa_vector_append.o: \
compile soa_vector_append.c dns.h
	./compile soa_vector_append.c

soa_vector_erase.o: \
compile soa_vector_erase.c dns.h
	./compile soa_vector_erase.c

soa_vector_ready.o: \
compile soa_vector_ready.c dns.h
	./compile soa_vector_ready.c

socket.lib: \
trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

tcpclient4.o: \
compile tcpclient4.c tcpclient4.h dnscache.h dn_vector.h client.h client4.h \
query.h query4.h log.h ioquery4.h udpclient4.h cache.h die.h \
tcpclient.c
	./compile tcpclient4.c

tcpclient6.o: \
compile tcpclient6.c tcpclient6.h dnscache.h dn_vector.h client.h client6.h \
query.h query6.h log.h ioquery6.h udpclient6.h cache.h die.h \
tcpclient.c
	./compile tcpclient6.c

tdlookup.o: \
compile tdlookup.c dns.h response.h tdlookup.h data_cdb.h die.h safe.h
	./compile tdlookup.c

tdlookup_loc_setup.o: \
compile tdlookup_loc_setup.c dns.h tdlookup.h data_cdb.h dns.h
	./compile tdlookup_loc_setup.c

tdlookup4.o: \
compile tdlookup4.c dns.h response.h tdlookup.h data_cdb.h respond.h
	./compile tdlookup4.c

tdlookup6.o: \
compile tdlookup6.c dns.h response.h tdlookup.h data_cdb.h respond.h
	./compile tdlookup6.c

test: \
prog
	./test_domain_constants
	./test_domain_name_decode
	./test_idna

test_domain_constants: \
load test_domain_constants.o die.a libdjbdns.a
	./load test_domain_constants die.a libdjbdns.a

test_domain_constants.o: \
compile test_domain_constants.c dns.h die.h
	./compile test_domain_constants.c

test_domain_name_decode: \
load test_domain_name_decode.o die.a libdjbdns.a
	./load test_domain_name_decode die.a libdjbdns.a

test_domain_name_decode.o: \
compile test_domain_name_decode.c dns.h die.h
	./compile test_domain_name_decode.c

test_idna: \
load test_idna.o die.a libdjbdns.a
	./load test_idna die.a libdjbdns.a

test_idna.o: \
compile test_idna.c dns.h die.h
	./compile test_idna.c

tinydns.8: \
sedit tinydns.mdoc
	./sedit tinydns.mdoc > tinydns.8

tinydns.0: \
mancat tinydns.8
	./mancat tinydns.8 > tinydns.0

tinydns: \
load tinydns.o server4.o droproot.o tdlookup4.o tdlookup_loc_setup.o \
tdlookup.o data_cdb.o qlog4.o qlog.o response.a safe.a die.a libdjbdns.a \
socket.lib
	./load tinydns server4.o droproot.o tdlookup4.o tdlookup_loc_setup.o \
	tdlookup.o data_cdb.o qlog4.o qlog.o response.a safe.a die.a \
	libdjbdns.a \
	`cat socket.lib`

tinydns-conf.8: \
sedit tinydns-conf.mdoc
	./sedit tinydns-conf.mdoc > tinydns-conf.8

tinydns-conf.0: \
mancat tinydns-conf.8
	./mancat tinydns-conf.8 > tinydns-conf.0

tinydns-conf: \
load tinydns-conf.o generic-conf.o auto_prefix.o die.a
	./load tinydns-conf generic-conf.o auto_prefix.o die.a

tinydns-conf.o: \
compile tinydns-conf.c auto_prefix.h generic-conf.h die.h
	./compile tinydns-conf.c

tinydns6.8: \
sedit tinydns6.mdoc
	./sedit tinydns6.mdoc > tinydns6.8

tinydns6.0: \
mancat tinydns6.8
	./mancat tinydns6.8 > tinydns6.0

tinydns6: \
load tinydns6.o server6.o droproot.o tdlookup6.o tdlookup_loc_setup.o \
tdlookup.o data_cdb.o qlog6.o qlog.o response.a safe.a die.a libdjbdns.a \
socket.lib
	./load tinydns6 server6.o droproot.o tdlookup6.o tdlookup_loc_setup.o \
	tdlookup.o data_cdb.o qlog6.o qlog.o response.a safe.a die.a \
	libdjbdns.a \
	`cat socket.lib`

tinydns6-conf.8: \
sedit tinydns6-conf.mdoc
	./sedit tinydns6-conf.mdoc > tinydns6-conf.8

tinydns6-conf.0: \
mancat tinydns6-conf.8
	./mancat tinydns6-conf.8 > tinydns6-conf.0

tinydns6-conf: \
load tinydns6-conf.o generic-conf.o auto_prefix.o die.a
	./load tinydns6-conf generic-conf.o auto_prefix.o die.a

tinydns6-conf.o: \
compile tinydns6-conf.c auto_prefix.h generic-conf.h die.h
	./compile tinydns6-conf.c

tinydns-bind2data.8: \
sedit tinydns-bind2data.mdoc
	./sedit tinydns-bind2data.mdoc > tinydns-bind2data.8

tinydns-bind2data.0: \
mancat tinydns-bind2data.8
	./mancat tinydns-bind2data.8 > tinydns-bind2data.0

tinydns-bind2data: \
load tinydns-bind2data.o whitespace.o die.a libdjbdns.a
	./load tinydns-bind2data whitespace.o die.a libdjbdns.a

tinydns-bind2data.o: \
compile tinydns-bind2data.c whitespace.h dns.h die.h
	./compile tinydns-bind2data.c

tinydns-data.8: \
sedit tinydns-data.mdoc
	./sedit tinydns-data.mdoc > tinydns-data.8

tinydns-data.0: \
mancat tinydns-data.8
	./mancat tinydns-data.8 > tinydns-data.0

tinydns-data: \
load tinydns-data.o whitespace.o die.a libdjbdns.a
	./load tinydns-data whitespace.o die.a libdjbdns.a

tinydns-data.o: \
compile tinydns-data.c whitespace.h dns.h die.h
	./compile tinydns-data.c

tinydns-edit.8: \
sedit tinydns-edit.mdoc
	./sedit tinydns-edit.mdoc > tinydns-edit.8

tinydns-edit.0: \
mancat tinydns-edit.8
	./mancat tinydns-edit.8 > tinydns-edit.0

tinydns-edit: \
load tinydns-edit.o whitespace.o die.a libdjbdns.a
	./load tinydns-edit whitespace.o die.a libdjbdns.a

tinydns-edit.o: \
compile tinydns-edit.c whitespace.h dns.h die.h
	./compile tinydns-edit.c

tinydns-get.1: \
sedit tinydns-get.mdoc
	./sedit tinydns-get.mdoc > tinydns-get.1

tinydns-get.0: \
mancat tinydns-get.1
	./mancat tinydns-get.1 > tinydns-get.0

tinydns-get: \
load tinydns-get.o tdlookup4.o tdlookup_loc_setup.o tdlookup.o data_cdb.o \
printpacket.o response.a safe.a die.a printrecord.o safe.a die.a libdjbdns.a
	./load tinydns-get tdlookup4.o tdlookup_loc_setup.o tdlookup.o \
	data_cdb.o printpacket.o printrecord.o response.a safe.a die.a libdjbdns.a

tinydns-get.o: \
compile tinydns-get.c response.h printpacket.h dns.h die.h
	./compile tinydns-get.c

tinydns-dnlist2data.8: \
sedit tinydns-dnlist2data.mdoc
	./sedit tinydns-dnlist2data.mdoc > tinydns-dnlist2data.8

tinydns-dnlist2data.0: \
mancat tinydns-dnlist2data.8
	./mancat tinydns-dnlist2data.8 > tinydns-dnlist2data.0

tinydns-dnlist2data: \
load tinydns-dnlist2data.o whitespace.o die.a libdjbdns.a
	./load tinydns-dnlist2data whitespace.o die.a libdjbdns.a

tinydns-dnlist2data.o: \
compile tinydns-dnlist2data.c whitespace.h dns.h die.h
	./compile tinydns-dnlist2data.c

tinydns-v1data2data.8: \
sedit tinydns-v1data2data.mdoc
	./sedit tinydns-v1data2data.mdoc > tinydns-v1data2data.8

tinydns-v1data2data.0: \
mancat tinydns-v1data2data.8
	./mancat tinydns-v1data2data.8 > tinydns-v1data2data.0

tinydns-v1data2data: \
load tinydns-v1data2data.o whitespace.o die.a libdjbdns.a
	./load tinydns-v1data2data whitespace.o die.a libdjbdns.a

tinydns-v1data2data.o: \
compile tinydns-v1data2data.c whitespace.h dns.h die.h
	./compile tinydns-v1data2data.c

tinydns-v3data2data.8: \
sedit tinydns-v3data2data.mdoc
	./sedit tinydns-v3data2data.mdoc > tinydns-v3data2data.8

tinydns-v3data2data.0: \
mancat tinydns-v3data2data.8
	./mancat tinydns-v3data2data.8 > tinydns-v3data2data.0

tinydns-v3data2data: \
load tinydns-v3data2data.o whitespace.o die.a libdjbdns.a
	./load tinydns-v3data2data whitespace.o die.a libdjbdns.a

tinydns-v3data2data.o: \
compile tinydns-v3data2data.c whitespace.h dns.h die.h
	./compile tinydns-v3data2data.c

tinydns.o: \
compile tinydns.c dns.h die.h respond.h
	./compile tinydns.c

tinydns6.o: \
compile tinydns6.c dns.h die.h respond.h
	./compile tinydns6.c

udpclient4.o: \
compile udpclient4.c dnscache.h dn_vector.h client.h client4.h query.h die.h \
query4.h ioquery4.h log.h udpclient4.h tcpclient4.h cache.h udpclient.c
	./compile udpclient4.c

udpclient6.o: \
compile udpclient6.c dnscache.h dn_vector.h client.h client6.h query.h die.h \
query6.h ioquery6.h log.h udpclient6.h tcpclient6.h cache.h udpclient.c
	./compile udpclient6.c

utime: \
load utime.o
	./load utime

utime.o: \
compile utime.c
	./compile utime.c

walldns.8: \
sedit walldns.mdoc
	./sedit walldns.mdoc > walldns.8

walldns.0: \
mancat walldns.8
	./mancat walldns.8 > walldns.0

walldns.o: \
compile walldns.c dns.h dd.h response.h respond.h
	./compile walldns.c

walldns: \
load walldns.o server4.o droproot.o qlog4.o qlog.o dd4.o response.a safe.a \
die.a libdjbdns.a socket.lib
	./load walldns server4.o droproot.o qlog4.o qlog.o dd4.o response.a \
	safe.a die.a libdjbdns.a \
	`cat socket.lib`

walldns-conf.8: \
sedit walldns-conf.mdoc
	./sedit walldns-conf.mdoc > walldns-conf.8

walldns-conf.0: \
mancat walldns-conf.8
	./mancat walldns-conf.8 > walldns-conf.0

walldns-conf: \
load walldns-conf.o generic-conf.o auto_prefix.o die.a
	./load walldns-conf generic-conf.o auto_prefix.o die.a

walldns-conf.o: \
compile walldns-conf.c auto_prefix.h generic-conf.h die.h
	./compile walldns-conf.c

walldns6.8: \
sedit walldns6.mdoc
	./sedit walldns6.mdoc > walldns6.8

walldns6.0: \
mancat walldns6.8
	./mancat walldns6.8 > walldns6.0

walldns6.o: \
compile walldns6.c dns.h dd.h response.h respond.h
	./compile walldns6.c

walldns6: \
load walldns6.o server6.o droproot.o qlog6.o qlog.o dd6.o response.a safe.a \
die.a libdjbdns.a socket.lib
	./load walldns6 server6.o droproot.o qlog6.o qlog.o dd6.o response.a \
	safe.a die.a libdjbdns.a \
	`cat socket.lib`

walldns6-conf.8: \
sedit walldns6-conf.mdoc
	./sedit walldns6-conf.mdoc > walldns6-conf.8

walldns6-conf.0: \
mancat walldns6-conf.8
	./mancat walldns6-conf.8 > walldns6-conf.0

walldns6-conf: \
load walldns6-conf.o generic-conf.o auto_prefix.o die.a
	./load walldns6-conf generic-conf.o auto_prefix.o die.a

walldns6-conf.o: \
compile walldns6-conf.c auto_prefix.h generic-conf.h die.h
	./compile walldns6-conf.c

whitespace.o: \
compile whitespace.c whitespace.h
	./compile whitespace.c

wilddns.8: \
sedit wilddns.mdoc
	./sedit wilddns.mdoc > wilddns.8

wilddns.0: \
mancat wilddns.8
	./mancat wilddns.8 > wilddns.0

wilddns: \
load wilddns.o server4.o dd4.o droproot.o qlog4.o qlog.o wildlookup.o \
data_cdb.o response.a safe.a die.a libdjbdns.a socket.lib
	./load wilddns wildlookup.o data_cdb.o server4.o dd4.o droproot.o \
	qlog4.o qlog.o response.a safe.a die.a libdjbdns.a \
	`cat socket.lib`

wilddns.o: \
compile wilddns.c dns.h respond.h wildlookup.h data_cdb.h
	./compile wilddns.c

wilddns6.8: \
sedit wilddns6.mdoc
	./sedit wilddns6.mdoc > wilddns6.8

wilddns6.0: \
mancat wilddns6.8
	./mancat wilddns6.8 > wilddns6.0

wilddns6: \
load wilddns6.o server6.o dd6.o droproot.o qlog6.o qlog.o wildlookup.o \
data_cdb.o response.a safe.a die.a libdjbdns.a socket.lib
	./load wilddns6 wildlookup.o data_cdb.o server6.o dd6.o droproot.o \
	qlog6.o qlog.o response.a safe.a die.a libdjbdns.a \
	`cat socket.lib`

wilddns6.o: \
compile wilddns6.c dns.h respond.h wildlookup.h data_cdb.h
	./compile wilddns6.c

wilddns-conf.8: \
sedit wilddns-conf.mdoc
	./sedit wilddns-conf.mdoc > wilddns-conf.8

wilddns-conf.0: \
mancat wilddns-conf.8
	./mancat wilddns-conf.8 > wilddns-conf.0

wilddns-conf: \
load wilddns-conf.o generic-conf.o auto_prefix.o die.a
	./load wilddns-conf generic-conf.o auto_prefix.o die.a

wilddns-conf.o: \
compile wilddns-conf.c auto_prefix.h generic-conf.h die.h
	./compile wilddns-conf.c

wilddns6-conf.8: \
sedit wilddns6-conf.mdoc
	./sedit wilddns6-conf.mdoc > wilddns6-conf.8

wilddns6-conf.0: \
mancat wilddns6-conf.8
	./mancat wilddns6-conf.8 > wilddns6-conf.0

wilddns6-conf: \
load wilddns6-conf.o generic-conf.o auto_prefix.o die.a
	./load wilddns6-conf generic-conf.o auto_prefix.o die.a

wilddns6-conf.o: \
compile wilddns6-conf.c auto_prefix.h generic-conf.h die.h
	./compile wilddns6-conf.c

wilddns-data.8: \
sedit wilddns-data.mdoc
	./sedit wilddns-data.mdoc > wilddns-data.8

wilddns-data.0: \
mancat wilddns-data.8
	./mancat wilddns-data.8 > wilddns-data.0

wilddns-data: \
load wilddns-data.o whitespace.o die.a libdjbdns.a
	./load wilddns-data whitespace.o die.a libdjbdns.a

wilddns-data.o: \
compile wilddns-data.c whitespace.h dns.h die.h
	./compile wilddns-data.c

wildlookup.o: \
compile dbllookup.c dns.h response.h respond.h wildlookup.h data_cdb.h die.h
	./compile wildlookup.c

debug.o: \
compile debug.c debug.h
	./compile debug.c
