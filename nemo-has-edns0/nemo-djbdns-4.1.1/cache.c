#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/alloc.h>
#include <nemo/byte.h>
#include <nemo/uint32.h>
#include <nemo/uint64.h>
#include <nemo/exit.h>
#include <nemo/unix.h>
#include <nemo/siphash.h>

#include "cache.h"
#include "log.h"
#include "die.h"

#define MAX_KEYLEN 1000
#define MAX_DATALEN 1000000

#define MIN_CACHE 4000
#define MAX_CACHE 4000000000

#define MAX_EXPIRE 604800

uint64_t cache_motion = 0;

static uint32_t min_ttl = MIN_TTL;

static byte_t siphash_key[16];
static byte_t *x_cache = 0;
static uint32_t x_size;
static uint32_t x_hsize;
static uint32_t x_writer;
static uint32_t x_oldest;
static uint32_t x_unused;

/*
  100 <= x_size <= 4000000000.
  4 <= x_hsize <= x_size/16.
  x_hsize is a power of 2.

  x_hsize <= x_writer <= x_oldest <= x_unused <= x_size.
  If x_oldest == x_unused then x_unused == x_size.

  x_cache is a hash table with the following structure:
  x_cache[0...x_hsize-1]: x_hsize/4 head links.
  x_cache[x_hsize...x_writer-1]: consecutive entries, newest entry on the right.
  x_cache[x_writer...x_oldest-1]: free space for new entries.
  x_cache[x_oldest...x_unused-1]: consecutive entries, oldest entry on the left.
  x_cache[x_unused...x_size-1]: unused.

  Each hash bucket is a linked list containing the following items:
  the head link, the newest entry, the second-newest entry,  etc.
  Each link is a 4-byte number giving the xor of
  the positions of the adjacent items in the list.

  Entries are always inserted immediately after the head and removed at the tail.

  Each entry contains the following information:
    uint32_t link;
    uint32_t keylen;
    uint32_t datalen;
    uint64_t expiretime;
    key;
    data.

  1st byte of data holds a data status condition. cf cache.h
*/

#define KEYLEN_OFFSET   4
#define DATALEN_OFFSET  8
#define EXPIRE_OFFSET   12
#define KEY_OFFSET      20

static void die_cache_impossible(void)
{
  _exit(111);
}

static void set4(register uint32_t pos, uint32_t u)
{
  if (pos > x_size - 4) die_cache_impossible();
  uint32_pack(u, x_cache + pos);
}

static uint32_t get4(register uint32_t pos)
{
  uint32_t result;
  if (pos > x_size - 4) die_cache_impossible();
  uint32_unpack(&result, x_cache + pos);
  return result;
}

static uint32_t hash(const byte_t *key, unsigned int keylen)
{
  uint64_t h;
  h = siphash24(key, keylen, siphash_key);
  return ((uint32_t) h) & (x_hsize - 4);
}

cache_t cache_get(const byte_t *key, unsigned int keylen, byte_t **data, unsigned int *datalen, uint32_t *ttl)
{
  register byte_t *x;
  uint64_t now;
  uint64_t expire;
  uint32_t pos;
  uint32_t prevpos;
  uint32_t nextpos;
  uint32_t u;
  unsigned int loop;
  byte_t status;
/*
  if (!x) return CACHE_MISS;
  if (keylen > MAX_KEYLEN) return CACHE_MISS;
*/
  prevpos = hash(key, keylen);
  pos = get4(prevpos);
  loop = 0;

  now = (uint64_t)unix_now();
  while (pos) {
    if (get4(pos + KEYLEN_OFFSET) == keylen) {
      if (pos + KEY_OFFSET + keylen > x_size) die_cache_impossible();
      x = x_cache + pos;
      if (byte_equal(key, keylen, x + KEY_OFFSET)) {  /* found it */
        uint64_unpack(&expire, x + EXPIRE_OFFSET);
        if (expire <= now) return CACHE_EXPIRED;  /* oops, expired */
        expire -= now;
        if (expire > MAX_EXPIRE) {
          expire = MAX_EXPIRE;
        }
        *ttl = (uint32_t)expire;
        u = get4(pos + DATALEN_OFFSET);
        if (u > x_size - pos - KEY_OFFSET - keylen) die_cache_impossible();
        *datalen = u - 1;
        x += (KEY_OFFSET + keylen);
        status = *x;
        *data = ++x;
        if (!datalen && status == CACHE_HIT) return CACHE_NXDOMAIN;
        return status;
      }
    }
    nextpos = prevpos ^ get4(pos);
    prevpos = pos;
    pos = nextpos;
    if (++loop > 100) {
      log_info("cache hash flood");
      return CACHE_MISS;  /* to protect against hash flooding */
    }
  }

  return CACHE_MISS;
}

cache_set_t cache_set(const byte_t *key, unsigned int keylen, unsigned int status, const byte_t *data, unsigned int datalen, uint32_t ttl)
{
  register byte_t *x;
  uint64_t now;
/*  uint64_t expire; */
  uint32_t keyhash;
  uint32_t pos;
  uint32_t prevpos;
  uint32_t nextpos;
  uint32_t len;
  unsigned int entrylen;
  unsigned int loop;
/*
  if (!x) return CACHE_SET_NOTALLOC;
  if (keylen > MAX_KEYLEN) return CACHE_SET_KEYLEN;
  if (datalen > MAX_DATALEN) return CACHE_SET_DATALEN;
*/
  if (ttl < min_ttl) {
    ttl = min_ttl;
  }
  else if (ttl > MAX_EXPIRE) {
    ttl = MAX_EXPIRE;  /* 1 week */
  }
/*
  try to reuse old entry
*/
  prevpos = hash(key, keylen);
  pos = get4(prevpos);
  loop = 0;

  now = (uint64_t)unix_now();
  while (pos) {
    if (get4(pos + KEYLEN_OFFSET) == keylen) {
      if (pos + KEY_OFFSET + keylen > x_size) die_cache_impossible();
      x = x_cache + pos;
      if (byte_equal(key, keylen, x + KEY_OFFSET)) {  /* found it */
        /* uint64_unpack(&expire, x + EXPIRE_OFFSET); */
        /* if (expire > now) return CACHE_SET_NOTEXPIRED; */
        /* treat all as expired */
        len = get4(pos + DATALEN_OFFSET);
        if (len == datalen + 1) {  /* we can use this */
          uint64_pack(now + (uint64_t)ttl, x + EXPIRE_OFFSET);  /* new expire */
          x += (KEY_OFFSET + keylen);
          *x = (byte_t)status;  /* flag */
          byte_copy(++x, datalen, data);  /* RRs */
          return CACHE_SET_OVERWRITE;
        }
        break;  /* ignore - eventually pushed off end of list */
      }
    }
    nextpos = prevpos ^ get4(pos);
    prevpos = pos;
    pos = nextpos;
    if (++loop > 100) break;
  }
/*
  add new entry at front of list --> newest at front, expired at back
*/
  entrylen = KEY_OFFSET + keylen + 1 + datalen;

  while (x_writer + entrylen > x_oldest) {
    if (x_oldest == x_unused) {
      if (x_writer <= x_hsize) {
        return CACHE_SET_EXHAUSTED;
      }
      x_unused = x_writer;
      x_oldest = x_hsize;
      x_writer = x_hsize;
    }

    pos = get4(x_oldest);
    set4(pos, get4(pos) ^ x_oldest);

    x_oldest += get4(x_oldest + 4) + get4(x_oldest + 8) + KEY_OFFSET;
    if (x_oldest > x_unused) die_cache_impossible();
    if (x_oldest == x_unused) {
      x_unused = x_size;
      x_oldest = x_size;
    }
  }

  keyhash = hash(key, keylen);

  pos = get4(keyhash);
  if (pos) {  /* insert at head */
    set4(pos, get4(pos) ^ keyhash ^ x_writer);
  }
  set4(x_writer, pos ^ keyhash);
  set4(x_writer + KEYLEN_OFFSET, keylen);
  set4(x_writer + DATALEN_OFFSET, datalen + 1);
  x = x_cache + x_writer;
  uint64_pack(now + (uint64_t)ttl, x + EXPIRE_OFFSET);
  x += KEY_OFFSET;
  byte_copy(x, keylen, key);
  x += keylen;
  *x = (byte_t)status;  /* flag */
  byte_copy(++x, datalen, data);  /* RRs */

  set4(keyhash, x_writer);
  x_writer += entrylen;
  cache_motion += entrylen;

  return CACHE_SET_NEW;
}

cache_set_t cache_expire(const byte_t *key, unsigned int keylen)
{
  register byte_t *x;
  uint32_t pos;
  uint32_t prevpos;
  uint32_t nextpos;
  unsigned int loop;
/*
  if (!x) return CACHE_SET_NOTALLOC;
  if (keylen > MAX_KEYLEN) return CACHE_SET_KEYLEN;
*/
  prevpos = hash(key, keylen);
  pos = get4(prevpos);
  loop = 0;

  while (pos) {
    if (get4(pos + KEYLEN_OFFSET) == keylen) {
      if (pos + KEY_OFFSET + keylen > x_size) die_cache_impossible();
      x = x_cache + pos;
      if (byte_equal(key, keylen, x + KEY_OFFSET)) {  /* found it */
        uint64_pack(0, x + EXPIRE_OFFSET);  /* overwrite expiry with zero */
        return CACHE_SET_OVERWRITE;
      }
    }
    nextpos = prevpos ^ get4(pos);
    prevpos = pos;
    pos = nextpos;
    if (++loop > 100) return CACHE_SET_HASHFLOOD;  /* to protect against hash flooding */
  }
  return CACHE_SET_NOTFOUND;
}

unsigned int cache_init(unsigned int cachesize, uint32_t minttl)
{
  unsigned int i;
  i = 0;
  do {
    siphash_key[i] = (byte_t)dns_random(256);
  } while (++i < sizeof siphash_key);
  if (x_cache) {
    alloc_free(x_cache);
    x_cache = 0;
  }

  if (cachesize > MAX_CACHE) {
    cachesize = MAX_CACHE;
  }
  if (cachesize < MIN_CACHE) {
    cachesize = MIN_CACHE;
  }
  x_size = cachesize;

  x_hsize = 4;
  while (x_hsize <= (x_size >> 5)) {
    x_hsize <<= 1;
  }

  x_cache = alloc(x_size);
  if (!x_cache) return 0;
  byte_zero(x_cache, x_size);

  x_writer = x_hsize;
  x_oldest = x_size;
  x_unused = x_size;

  if (minttl) {
    min_ttl = minttl;
  }
  if (min_ttl < MIN_TTL) {
    min_ttl = MIN_TTL;
  }

  return 1;
}
