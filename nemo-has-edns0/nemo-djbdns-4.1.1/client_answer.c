/*
        This is included by:    client4_answer.c
                                client6_answer.c
*/

query_cache_t client_answer(client *z)
{
  static dns_domain t1 = DNS_DOMAIN;
  static dns_domain t2 = DNS_DOMAIN;
  static dns_domain qname = DNS_DOMAIN;
  static dns_domain cname = DNS_DOMAIN;
  byte_t key[257];
  byte_t misc[20];
  ip4_address ip4;
  ip6_address ip6;
  byte_t *cached;
  dns_type *qtype;
  unsigned int key_len;
  unsigned int cached_len;
  unsigned int pos;
  unsigned int flag_any;
  unsigned int type;
  unsigned int status;
  unsigned int loop;
  uint32_t ttl;
  uint16_t data_len;

  qtype = &z->type;
  type = dns_type_get(qtype);
  flag_any = (type == DNS_T_ANY);

  if (type == DNS_T_AXFR) return R_FAIL;
  if (type == DNS_T_IXFR) return R_FAIL;
  if (type == DNS_T_OPT) return R_FAIL;

  if (!dns_domain_copy(&qname, &z->name)) die_nomem();
  if (!response_query(&qname, qtype, &z->class)) return R_FAIL;

  if (global_ip4(&qname, &ip4)) {
    if (!response_rr_start(&qname, dns_t_a, 655360)) return R_FAIL;
    if (!response_addip4(&ip4)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (global_ip6(&qname, &ip6)) {
    if (!response_rr_start(&qname, dns_t_aaaa, 655360)) return R_FAIL;
    if (!response_addip6(&ip6)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_any_inaddr_arpa)) {  /* short cut */
    response_nxdomain();
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_localhost_inaddr_arpa)) {
    if (!response_rr_start(&qname, dns_t_ptr, 655360)) return R_FAIL;
    if (!response_addname(dns_d_ip4_localhost)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_any_ip6_arpa)) {  /* short cut */
    response_nxdomain();
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_localhost_ip6_arpa)) {
    if (!response_rr_start(&qname, dns_t_ptr, 655360)) return R_FAIL;
    if (!response_addname(dns_d_ip6_localhost)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_localnet_ip6_arpa)) {
    if (!response_rr_start(&qname, dns_t_ptr, 655360)) return R_FAIL;
    if (!response_addname(dns_d_ip6_localnet)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_mcastprefix_ip6_arpa)) {
    if (!response_rr_start(&qname, dns_t_ptr, 655360)) return R_FAIL;
    if (!response_addname(dns_d_ip6_mcastprefix)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_allnodes_ip6_arpa)) {
    if (!response_rr_start(&qname, dns_t_ptr, 655360)) return R_FAIL;
    if (!response_addname(dns_d_ip6_allnodes)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_allrouters_ip6_arpa)) {
    if (!response_rr_start(&qname, dns_t_ptr, 655360)) return R_FAIL;
    if (!response_addname(dns_d_ip6_allrouters)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  if (dns_domain_equal(&qname, dns_d_allhosts_ip6_arpa)) {
    if (!response_rr_start(&qname, dns_t_ptr, 655360)) return R_FAIL;
    if (!response_addname(dns_d_ip6_allhosts)) return R_FAIL;
    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    return R_FOUND_OK;
  }

  loop = 0;
  for (;;) {  /* cname resolution loop */
    if (++loop == MAX_ALIAS) {
      log_local_fail(&z->name, dns_t_cname, "cname chain length exceeded");
      return R_FAIL;
    }
    key_len = cache_make_key(dns_t_cname, &qname, key);
    status = cache_get(key, key_len, &cached, &cached_len, &ttl);
    if (status == CACHE_HIT) {
      if (!safe_packet_getname(cached, cached_len, 0, &cname)) return R_FAIL;
      if (!response_cname(&qname, &cname, ttl)) return R_FAIL;
      if (!dns_domain_copy(&qname, &cname)) die_nomem();
      if (type == DNS_T_CNAME) return R_FOUND_OK;
      continue;  /* retry */
    }
    break;
  }  /* end: cname resolution loop */

  key_len = cache_make_key(qtype, &qname, key);
  if (!flag_any) {
    status = cache_get(key, key_len, &cached, &cached_len, &ttl);
    if (status == CACHE_HIT) {
      switch (type) {
        case DNS_T_NS:
          pos = 0;
          for (;;) {
            pos = safe_packet_getname(cached, cached_len, pos, &t1);
            if (!pos) break;
            if (!response_rr_start(&qname, dns_t_ns, ttl)) return R_FAIL;
            if (!response_addname(&t1)) return R_FAIL;
            response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
          }
          break;
        case DNS_T_PTR:
	  pos = 0;
	  for (;;) {
	    pos = safe_packet_getname(cached, cached_len, pos, &t1);
	    if (!pos) break;
	    if (!response_rr_start(&qname, dns_t_ptr, ttl)) return R_FAIL;
	    if (!response_addname(&t1)) return R_FAIL;
	    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
	  }
          break;
        case DNS_T_MX:
	  pos = 0;
	  for (;;) {
	    pos = dns_packet_copy(cached, cached_len, pos, misc, 2);
	    if (!pos) break;
	    pos = safe_packet_getname(cached, cached_len, pos, &t1);
	    if (!pos) break;
	    if (!response_rr_start(&qname, dns_t_mx, ttl)) return R_FAIL;
	    if (!response_addbytes(misc, 2)) return R_FAIL;
	    if (!response_addname(&t1)) return R_FAIL;
	    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
	  }
          break;
        case DNS_T_SOA:
	  pos = 0;
	  for (;;) {
	    pos = dns_packet_copy(cached, cached_len, pos, misc, 20);
	    if (!pos) break;
	    pos = safe_packet_getname(cached, cached_len, pos, &t1);
	    if (!pos) break;
	    pos = safe_packet_getname(cached, cached_len, pos, &t2);
	    if (!pos) break;
	    if (!response_rr_start(&qname, dns_t_soa, ttl)) return R_FAIL;
	    if (!response_addname(&t1)) return R_FAIL;
	    if (!response_addname(&t2)) return R_FAIL;
	    if (!response_addbytes(misc, 20)) return R_FAIL;
	    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
	  }
          break;
        case DNS_T_A:
	  while (cached_len >= 4) {
	    if (!response_rr_start(&qname, dns_t_a, ttl)) return R_FAIL;
	    if (!response_addbytes(cached, 4)) return R_FAIL;
	    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
	    cached += 4;
	    cached_len -= 4;
	  }
          break;
        case DNS_T_AAAA:
	  while (cached_len >= 16) {
	    if (!response_rr_start(&qname, dns_t_aaaa, ttl)) return R_FAIL;
	    if (!response_addbytes(cached, 16)) return R_FAIL;
	    response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
	    cached += 16;
	    cached_len -= 16;
	  }
          break;
        default:
          while (cached_len >= 2) {
            uint16_unpack_big(&data_len, cached);
            cached += 2;
            cached_len -= 2;
            if (data_len > cached_len) return R_FAIL;
            if (!response_rr_start(&qname, qtype, ttl)) return R_FAIL;
            if (!response_addbytes(cached, data_len)) return R_FAIL;
            response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
            cached += data_len;
            cached_len -= data_len;
          }
          break;
      }
      return R_FOUND_OK;
    }
    if (status == CACHE_NXDOMAIN) {
      response_nxdomain();
      return R_FOUND_OK;
    }
    if (status == CACHE_SERVFAIL) {
      response_servfail();
      return R_FOUND_OK;
    }
    return R_NOT_FOUND;
  }

  /* process ANY RR */

  dns_type_pack(dns_t_ns, key);
  status = cache_get(key, key_len, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    pos = 0;
    for (;;) {
      pos = safe_packet_getname(cached, cached_len, pos, &t1);
      if (!pos) break;
      if (!response_rr_start(&qname, dns_t_ns, ttl)) return R_FAIL;
      if (!response_addname(&t1)) return R_FAIL;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
  }

  dns_type_pack(dns_t_ptr, key);
  status = cache_get(key, key_len, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    pos = 0;
    for (;;) {
      pos = safe_packet_getname(cached, cached_len, pos, &t1);
      if (!pos) break;
      if (!response_rr_start(&qname, dns_t_ptr, ttl)) return R_FAIL;
      if (!response_addname(&t1)) return R_FAIL;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
  }

  dns_type_pack(dns_t_mx, key);
  status = cache_get(key, key_len, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    pos = 0;
    for (;;) {
      pos = dns_packet_copy(cached, cached_len, pos, misc, 2);
      if (!pos) break;
      pos = safe_packet_getname(cached, cached_len, pos, &t1);
      if (!pos) break;
      if (!response_rr_start(&qname, dns_t_mx, ttl)) return R_FAIL;
      if (!response_addbytes(misc, 2)) return R_FAIL;
      if (!response_addname(&t1)) return R_FAIL;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
  }

  dns_type_pack(dns_t_soa, key);
  status = cache_get(key, key_len, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    pos = 0;
    for (;;) {
      pos = dns_packet_copy(cached, cached_len, pos, misc, 20);
      if (!pos) break;
      pos = safe_packet_getname(cached, cached_len, pos, &t1);
      if (!pos) break;
      pos = safe_packet_getname(cached, cached_len, pos, &t2);
      if (!pos) break;
      if (!response_rr_start(&qname, dns_t_soa, ttl)) return R_FAIL;
      if (!response_addname(&t1)) return R_FAIL;
      if (!response_addname(&t2)) return R_FAIL;
      if (!response_addbytes(misc, 20)) return R_FAIL;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
    }
  }

  dns_type_pack(dns_t_a, key);
  status = cache_get(key, key_len, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    while (cached_len >= 4) {
      if (!response_rr_start(&qname, dns_t_a, ttl)) return R_FAIL;
      if (!response_addbytes(cached, 4)) return R_FAIL;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
      cached += 4;
      cached_len -= 4;
    }
  }

  dns_type_pack(dns_t_aaaa, key);
  status = cache_get(key, key_len, &cached, &cached_len, &ttl);
  if (status == CACHE_HIT) {
    while (cached_len >= 16) {
      if (!response_rr_start(&qname, dns_t_aaaa, ttl)) return R_FAIL;
      if (!response_addbytes(cached, 16)) return R_FAIL;
      response_rr_finish(DNS_HEADER_ANSWER_COUNT_OFFSET);
      cached += 16;
      cached_len -= 16;
    }
  }

  return R_FOUND_OK;  /* RR == ANY */
}
