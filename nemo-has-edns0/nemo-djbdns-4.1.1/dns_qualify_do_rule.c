#include <nemo/byte.h>

#include "dns.h"

unsigned int dns_qualify_do_rule(stralloc *work, const stralloc *rule)
{
  char *d;
  char rule_type;
  unsigned int len;
  unsigned int colon;
  unsigned int prefixlen;

  d = rule->s;
  len = rule->len;
  rule_type = *d++;
  if (!len) return 1;  /* empty rule */
  len--;
  if ((rule_type != '?') && (rule_type != '=') && (rule_type != '*') && (rule_type != '-')) return 1;
  colon = byte_chr(d, len, ':');
  if (colon == len) return 1;

  if (work->len < colon) return 1;
  prefixlen = work->len - colon;
  if ((rule_type == '=') && prefixlen) return 1;
  if (byte_case_diff(d, colon, work->s + prefixlen)) return 1;
  if (rule_type == '?') {
    if (byte_chr(work->s, prefixlen, '.') < prefixlen) return 1;
    if (byte_chr(work->s, prefixlen, ':') < prefixlen) return 1;
    if (byte_chr(work->s, prefixlen, '[') < prefixlen) return 1;
    if (byte_chr(work->s, prefixlen, ']') < prefixlen) return 1;
  }

  work->len = prefixlen;
  if (rule_type == '-') {
    work->len = 0;
  }
  return stralloc_catb(work, d + colon + 1, len - colon - 1);
}
