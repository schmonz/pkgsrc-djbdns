#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/uint32.h>
#include <nemo/ip4.h>
#include <nemo/unix.h>

#include "dns.h"

static uint32_t seed[32];
static uint32_t in[12];
static uint32_t out[8];
static int outleft = 0;

#define ROTATE(x, b)  (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i, b)  x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x, b))

static void surf(void)
{
  uint32_t t[12];
  uint32_t x;
  uint32_t sum;
  unsigned int r;
  unsigned int i;
  unsigned int loop;

  sum = 0;
  for (i = 0; i < 12; ++i) {
    t[i] = in[i] ^ seed[12 + i];
  }
  for (i = 0; i < 8; ++i) {
    out[i] = seed[24 + i];
  }
  x = t[11];
  for (loop = 0; loop < 2; ++loop) {
    for (r = 0; r < 16; ++r) {
      sum += 0x9e3779b9;
      MUSH(0, 5);
      MUSH(1, 7);
      MUSH(2, 9);
      MUSH(3, 13);
      MUSH(4, 5);
      MUSH(5, 7);
      MUSH(6, 9);
      MUSH(7, 13);
      MUSH(8, 5);
      MUSH(9, 7);
      MUSH(10, 9);
      MUSH(11, 13);
    }
    for (i = 0; i < 8; ++i) {
      out[i] ^= t[i + 4];
    }
  }
}

void dns_random_init(const char data[128])
{
  unsigned int i;
  struct taia t;
  char tpack[16];

  for (i = 0; i < 32; ++i) {
    uint32_unpack(seed + i, data + 4 * i);
  }

  taia_now(&t);
  taia_pack(&t, tpack);
  for (i = 0; i < 4; ++i) {
    uint32_unpack(in + 4 + i, tpack + 4 * i);
  }

  in[8] = (uint32_t)getpid();
  in[9] = (uint32_t)getppid();
  /* more space in 10 and 11, but this is probably enough */
}

unsigned int dns_random(unsigned int n)
{
  if (!n) return 0;

  if (!outleft) {
    if (!++in[0]) {
      if (!++in[1]) {
        if (!++in[2]) {
          ++in[3];
        }
      }
    }
    surf();
    outleft = 8;
  }

  return out[--outleft] % n;
}
