#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/uint32.h>
#include <nemo/uint16.h>
#include <nemo/byte.h>
#include <nemo/char.h>
#include <nemo/fmt.h>
#include <nemo/error.h>

#include "dns.h"
#include "log.h"

void log_char(char c)
{
  djbio_put(djbiofd_out, &c, 1);
}

void log_hex(byte_t c)
{
  djbio_put(djbiofd_out, &char_hex_chars[(c >> 4)], 1);
  djbio_put(djbiofd_out, &char_hex_chars[(c & 15)], 1);
}

void log_number(uint64_t l)
{
  char fmtstr[FMT_ULONG];
  djbio_put(djbiofd_out, fmtstr, fmt_ulong(fmtstr, (unsigned long)l));
}

void log_string(const char *s)
{
  djbio_puts(djbiofd_out, s);
}

void log_prefix(const char *s)
{
  djbio_puts(djbiofd_out, s);
  djbio_put(djbiofd_out, " ", 1);
}

void log_line(void)
{
  djbio_put(djbiofd_out, "\n", 1);
  djbio_flush(djbiofd_out);
}

void log_space(void)
{
  djbio_put(djbiofd_out, " ", 1);
}

void log_colon(void)
{
  djbio_put(djbiofd_out, ":", 1);
}

void log_ip4(const ip4_address *ip)
{
  char fmtstr[IP4_FMT];
  djbio_put(djbiofd_out, fmtstr, ip4_fmt(ip, fmtstr));
}

void log_ip6(const ip6_address *ip)
{
  char fmtstr[IP6_FMT];
  djbio_put(djbiofd_out, fmtstr, ip6_fmt(ip, fmtstr));
}

void log_id(const dns_id *id)
{
  log_number(id->d);
}

void log_type(const dns_type *type)
{
  const char *x;

  x = dns_type_str(type->d);
  if (x) {
    log_string(x);
  }
  else {
    log_number(type->d);
  }
}

void log_domain(const dns_domain *q)
{
  const byte_t *d;
  unsigned int plen;  /* prefix length */
  byte_t ch;

  if (!dns_domain_labellength(q)) {
    log_char('.');
    return;
  }
  d = q->data;
  while ((plen = (unsigned int)*d++)) {
    while (plen) {
      ch = *d++;
      plen--;
      if ((ch <= 32) || (ch > 126)) {
        ch = '?';
      }
      else if ((ch >= 'A') && (ch <= 'Z')) {
        ch = (byte_t)(ch + 32);
      }
      djbio_put(djbiofd_out, &ch, 1);
    }
    log_char('.');
  }
}

void log_rcode(unsigned rcode)
{
  const char *x;

  x = dns_rcode_str(rcode);
  if (x) {
    log_string(x);
  }
  else {
    log_number(rcode);
  }
}

void log_startup(unsigned int cachesize, uint32_t minttl, unsigned int flag_edns0)
{
  log_prefix("starting");
  log_number(cachesize);
  log_space();
  log_number(minttl);
  log_space();
  if (!flag_edns0) {
    log_string("no-");
  }
  log_string("edns0");
  log_line();
}

void log_tx_piggyback(uint64_t qnum, const dns_domain *qname, const dns_type *qtype, const dns_domain *control)
{
  log_prefix("tx");
  log_number(qnum);
  log_string(" pb ");
  log_type(qtype);
  log_space();
  log_domain(qname);
  log_space();
  log_domain(control);
  log_line();
}

void log_tx_error(uint64_t qnum)
{
  log_prefix("tx");
  log_number(qnum);
  log_string(" error ");
  log_string(error_str(errno));
  log_line();
}

void log_cacheset(const char *what, const char *suffix, const dns_domain *dname, const dns_type *type, unsigned int data_len)
{
  log_string("cache-");
  log_string(what);
  log_string(suffix);
  log_space();
  log_type(type);
  log_space();
  log_domain(dname);
  log_space();
  log_number(data_len);
  log_line();
}

void log_remote_fail(const dns_domain *dname, const dns_type *type)
{
  log_prefix("remote-fail");
  log_type(type);
  log_space();
  log_domain(dname);
  log_line();
}

void log_local_fail(const dns_domain *dname, const dns_type *type, const char *reason)
{
  log_prefix("local-fail");
  log_type(type);
  log_space();
  log_domain(dname);
  log_space();
  log_string(reason);
  log_line();
}

static void log_ns_error(const char *error, const dns_domain *dname, const dns_domain *control)
{
  log_prefix(error);
  log_domain(dname);
  log_space();
  log_domain(control);
  log_line();
}

void log_ns_loop(const dns_domain *dname, const dns_domain *control)
{
  log_ns_error("ns-loop", dname, control);
}

void log_ns_cname(const dns_domain *dname, const dns_domain *control)
{
  log_ns_error("ns-cname", dname, control);
}

void log_ns_fail(const dns_domain *dname, const dns_domain *control)
{
  log_ns_error("ns-fail", dname, control);
}

void log_rejected_source_port(unsigned int port)
{
  log_prefix("rejected source-port");
  log_number(port);
  log_line();
}

void log_info(const char *comment)
{
  log_prefix("info");
  log_string(comment);
  log_line();
}
