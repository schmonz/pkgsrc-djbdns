#include <nemo/stdint.h>
#include <nemo/uint32.h>
#include <nemo/uint32_vector.h>
#include <nemo/error.h>
#include <nemo/stralloc.h>

#include "dns.h"

/*
  1 --> OK
  0 --> protcol error
*/

/*
  dns_idna_encode() converts UTF-8 to IDNA.
*/

/*
original code:
punycode.c from RFC 3492
http://www.nicemice.net/idn/
Adam M. Costello
http://www.nicemice.net/amc/
*/

#define DELIMITER '-'

/*
  bootstring parameters for punycode
*/
enum {
  BASE = 36,
  TMIN = 1,
  TMAX = 26,
  SKEW = 38,
  DAMP = 700,
  INITIAL_BIAS = 72,
  INITIAL_N = 0x80
};

/*
  platform-specific constants
*/
/*
  maxint is the maximum value of a uint32_t variable
*/
static const uint32_t maxint = 0xffffffff;
/*
  basic(cp) tests whether cp is a basic code point
*/
#define basic(cp) ((cp) < 0x00000080)
/*
  encode_digit(d)

  returns the basic code point whose value (when used for representing
  integers) is d, which needs to be in the range 0 to base-1.

   0..25 map to ASCII a..z
  26..35 map to ASCII 0..9
*/
static const byte_t encoded_digits_table[BASE] = {
'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9'
};

static byte_t encode_digit(uint32_t d)
{
  return encoded_digits_table[d];
  /* return d + 22 + 75 * (d < 26); */
}
/*
  bias adaptation function
*/
static uint32_t adapt(uint32_t delta, uint32_t num_points, unsigned int flag_first_time)
{
  uint32_t k;
  delta = (flag_first_time) ? delta / DAMP : delta >> 1;
  /* delta >> 1 is a faster way of doing delta / 2 */
  delta += delta / num_points;
  for (k = 0; delta > ((BASE - TMIN) * TMAX) / 2; k += BASE) {
    delta /= BASE - TMIN;
  }
  return k + (BASE - TMIN + 1) * delta / (delta + SKEW);
}
/*
  main encode function
*/
static unsigned int do_punycode_encode(stralloc *out, const uint32_vector *in)
{
  uint32_t n;
  uint32_t q;
  uint32_t k;

  const uint32_t *input;
  unsigned int input_len;
  unsigned int count_basic;  /* number of basic code points */
  unsigned int count_handled;  /* number of code points that have been handled */
  unsigned int j;
  uint32_t delta;
  uint32_t bias;
  uint32_t max;
  uint32_t i;
  uint32_t t;
  byte_t ch;
/*
  Initialize the state
*/
  input = in->va;
  input_len = in->len;

  bias = INITIAL_BIAS;
  delta = 0;
  n = INITIAL_N;

  if (!stralloc_erase(out)) return 0;
/*
  handle the basic code points
*/
  for (j = 0; j < input_len; ++j) {
    i = input[j];
    if (basic(i)) {
      ch = (byte_t)i;
      if (!stralloc_append(out, &ch)) return 0;
    }
  }

  if (out->len == input_len) return 1;

  count_handled = count_basic = out->len;

  if (out->len) {
    ch = DELIMITER;
    if (!stralloc_append(out, &ch)) return 0;
  }
/*
  main encoding loop
*/
  while (count_handled < input_len) {
/*
    All non-basic code points < n have been handled already.
    Find the next larger one
*/
    max = maxint;
    for (j = 0; j < input_len; ++j) {
      i = input[j];
      /* if (basic(i)) continue; */  /* redundant */
      if (i >= n && i < max) {
        max = i;
      }
    }
/*
    Increase delta enough to advance the decoder's
    <n,i> state to <m,0>, but guard against overflow:
*/
    if (max - n > (maxint - delta) / (count_handled + 1)) {
      errno = error_proto;
      return 0;
    }
    delta += (max - n) * (count_handled + 1);
    n = max;

    for (j = 0; j < input_len; ++j) {
      /* do not need to check whether input[j] is basic */
      i = input[j];
      if (i < n /* || basic(i) */ ) {
	if (++delta == 0) {
          errno = error_proto;
	  return 0;
	}
      }

      if (i == n) {
	/* Represent delta as a generalized variable-length integer: */

	for (q = delta, k = BASE; ; k += BASE) {
	  t = (k <= bias /* + TMIN */)     /* +TMIN not needed */
	        ? TMIN
	        : (k >= bias + TMAX) ? TMAX : k - bias;
	  if (q < t) break;
	  ch = encode_digit(t + (q - t) % (BASE - t));
          if (!stralloc_append(out, &ch)) return 0;
	  q = (q - t) / (BASE - t);
        }
	ch = encode_digit(q);
        if (!stralloc_append(out, &ch)) return 0;
	bias = adapt(delta, count_handled + 1, count_handled == count_basic);
	delta = 0;
	++count_handled;
      }
    }
    ++delta;
    ++n;
  }
  return 1;
}

static unsigned int do_encode(stralloc *out, const stralloc *in)
{
  static uint32_vector unicode_data = UINT32_VECTOR;
  static stralloc tmp = STRALLOC;

  if (!uint32_vector_utf8_decode(&unicode_data, in->s, in->len)) return 0;
  uint32_vector_lower(&unicode_data);
  if (!do_punycode_encode(&tmp, &unicode_data)) return 0;
  if (!stralloc_erase(out)) return 0;
  if (stralloc_case_diff(in, &tmp)) {
    if (!stralloc_copyb(out, "xn--", 4)) return 0;
  }
  return stralloc_cat(out, &tmp);
}

unsigned int dns_idna_encode(stralloc *out, const stralloc *in)
{
  static sa_vector parts = SA_VECTOR;
  static stralloc tmp = STRALLOC;
  unsigned int i;

  if (!sa_vector_parse(&parts, in, ".", 1)) return 0;
  if (!stralloc_erase(out)) return 0;
  for (i = 0; i < parts.len; i++) {
    if (out->len) {
      if (!stralloc_append(out, ".")) return 0;
    }
    if (!do_encode(&tmp, &parts.va[i])) return 0;
    if (!stralloc_cat(out, &tmp)) return 0;
  }
  return 1;
}
