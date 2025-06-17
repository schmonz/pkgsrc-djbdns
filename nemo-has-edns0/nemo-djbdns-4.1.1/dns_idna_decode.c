#include "stdint.h"
#include "uint32.h"
#include "uint32_vector.h"
#include "error.h"

/*
  1 --> OK
  0 --> protcol error
*/

/*
  dns_punycode_encode() converts Unicode to Punycode.

  The input is represented as an array of Unicode code points (not code units;
  surrogate pairs are not allowed), and the output will be represented as an
  array of ASCII code points.

  The output string is *not* null-terminated; it will contain zeros if and only
  if the input contains zeros.

  The case_flags array
holds input_len boolean values, where nonzero suggests that
the corresponding Unicode character be forced to uppercase
after being decoded (if possible), and zero suggests that
it be forced to lowercase (if possible).

  ASCII code points
are encoded literally, except that ASCII letters are forced
to uppercase or lowercase according to the corresponding
uppercase flags.  If case_flags is a null pointer then ASCII
letters are left as they are, and other code points are
treated as if their uppercase flags were zero.

  The return
value can be any of the punycode_status values defined above
except punycode_bad_input; if not punycode_success, then
output_size and output might contain garbage.
*/

#define DELIMITER '-'

/*** Bootstring parameters for Punycode ***/

enum {
  BASE = 36,
  TMIN = 1,
  TMAX = 26,
  SKEW = 38,
  DAMP = 700,
  INITIAL_BIAS = 72,
  INITIAL_N = 0x80,
};

/* basic(cp) tests whether cp is a basic code point: */
#define basic(cp) ((cp) < 0x00000080)

/* delim(cp) tests whether cp is a DELIMITER: */
#define delim(cp) ((cp) == DELIMITER)

/*
  decode_digit(cp)

  returns the numeric value of a basic code point
  (for use in representing integers) in the range 0 to
  base-1, or base if cp is does not represent a value.
*/
static uint32_t decode_digit(uint32_t cp)
{
  if (cp - 48 < 10) return cp - 22;
  if (cp - 65 < 26) return cp - 65;
  if (cp - 97 < 26) return cp - 97;
  return BASE;
}

/*
  encode_digit(d,flag)

  returns the basic code point whose value (when used for representing
  integers) is d, which needs to be in the range 0 to base-1.

  The lowercase form is used unless flag is nonzero, in which case the
  uppercase form is used.

  The behavior is undefined if flag is nonzero and digit d has no uppercase
  form.
*/
static byte_t encode_digit(uint32_t d, int flag)
{
  return d + 22 + 75 * (d < 26) - ((flag != 0) << 5);
  /*  0..25 map to ASCII a..z or A..Z */
  /* 26..35 map to ASCII 0..9         */

}
/* flagged(bcp) tests whether a basic code point is flagged */
/* (uppercase).  The behavior is undefined if bcp is not a  */
/* basic code point.                                        */

#define flagged(bcp) ((uint32_t)(bcp) - 65 < 26)
/* encode_basic(bcp,flag) forces a basic code point to lowercase */
/* if flag is zero, uppercase if flag is nonzero, and returns    */
/* the resulting code point.  The code point is unchanged if it  */
/* is caseless.  The behavior is undefined if bcp is not a basic */
/* code point.                                                   */

static char encode_basic(uint32_t bcp, int flag)
{
  bcp -= (bcp - 97 < 26) << 5;
  return bcp + ((!flag && (bcp - 65 < 26)) << 5);
}

/*** Platform-specific constants ***/
/* maxint is the maximum value of a uint32_t variable: */
static const uint32_t maxint = -1;
/* Because maxint is unsigned, -1 becomes the maximum value. */

/*
  bias adaptation function
*/
static uint32_t adapt(uint32_t delta, uint32_t num_points, int flag_first_time)
{
  uint32_t k;
  delta = (flag_first_time) ? delta / DAMP : delta >> 1;
  /* delta >> 1 is a faster way of doing delta / 2 */
  delta += delta / num_points;
  for (k = 0; delta > ((base - TMIN) * TMAX) / 2; k += base) {
    delta /= base - TMIN;
  }
  return k + (base - TMIN + 1) * delta / (delta + SKEW);
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
  byte_t *x;
  byte_t ch;
/*
  Initialize the state
*/
  input = &in->va;
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

  if (out) {
    if (!stralloc_append(out, "-")) return 0;
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

	for (q = delta, k = base; ; k += base) {
	  t = (k <= bias /* + TMIN */)     /* +TMIN not needed */
	        ? TMIN
	        : (k >= bias + TMAX) ? TMAX : k - bias;
	  if (q < t) break;
	  ch = encode_digit(t + (q - t) % (base - t), 0);
          if (!stralloc_append(out, &ch)) return 0;
	  q = (q - t) / (base - t);
        }
	ch = encode_digit(q, case_flags && case_flags[j]);
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

unsigned int dns_punycode_encode(stralloc *out, const stralloc *in)
{
  static uint32_vector unicode_data = UINT32_VECTOR;

  if (!uint32_vector_utf8_decode(&unicode_data, in->d, in->len)) return 0;
  return (do_punycode_encode(out, &unicode_data));
}
