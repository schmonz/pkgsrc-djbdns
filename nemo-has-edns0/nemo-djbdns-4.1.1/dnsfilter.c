#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/alloc.h>
#include <nemo/byte.h>
#include <nemo/scan.h>
#include <nemo/tai.h>
#include <nemo/taia.h>
#include <nemo/sgetopt.h>
#include <nemo/error.h>
#include <nemo/exit.h>
#include <nemo/ip4.h>
#include <nemo/iopause.h>
#include <nemo/unix.h>

#include "dns.h"
#include "die.h"

const char USAGE[] = "[ -c concurrency ] [ -l lines ]";

static struct line {
  stralloc left;
  stralloc middle;
  stralloc right;
  struct dns4_transmit dt;
  unsigned int flag_active;
  iopause_fd *io;
} *x;
static struct line tmp;
static unsigned int xmax = 1000;
static unsigned int xnum = 0;
static unsigned int numactive = 0;
static unsigned int maxactive = 10;

static stralloc partial = STRALLOC;
static sa_vector name_list = SA_VECTOR;

static byte_t inbuf[1024];
static unsigned int inbuflen = 0;
static iopause_fd *inio;
static unsigned int flag0 = 1;

static iopause_fd *io;
static unsigned int iolen;

static ip4_vector servers = IP4_VECTOR;
static ip4_address ip;
static dns_domain name = DNS_DOMAIN;

static void errout(unsigned int i)
{
  unsigned int j;

  if (!stralloc_copys(&x[i].middle, ":")) die_nomem();
  if (!stralloc_cats(&x[i].middle, error_str(errno))) die_nomem();
  for (j = 0; j < x[i].middle.len; ++j) {
    if (x[i].middle.s[j] == ' ') {
      x[i].middle.s[j] = '-';
    }
  }
}

int main(int argc, char **argv)
{
  struct taia stamp;
  struct taia deadline;
  int opt;
  unsigned long u;
  unsigned int i;
  unsigned int j;
  ssize_t r;

  PROGRAM = *argv;
  while ((opt = getopt(argc, argv, "c:l:")) != opteof)
    switch(opt) {
      case 'c':
        scan_ulong(optarg, &u);
        if (u < 1) u = 1;
        if (u > 1000) u = 1000;
        maxactive = (unsigned int)u;
        break;
      case 'l':
        scan_ulong(optarg, &u);
        if (u < 1) u = 1;
        if (u > 1000000) u = 1000000;
        xmax = (unsigned int)u;
        break;
      default:
        die_usage();
        break;
    }

  x = (struct line *) alloc(xmax * sizeof(struct line));
  if (!x) die_nomem();
  byte_zero((void*)x, (unsigned int)(xmax * sizeof(struct line)));
  for (i = 0; i < xmax; i++) {
    dns4_transmit_init(&(x[i].dt));
  }

  io = (iopause_fd *) alloc((xmax + 1) * sizeof(iopause_fd));
  if (!io) die_nomem();

  if (!stralloc_erase(&partial)) die_nomem();


  while (flag0 || inbuflen || partial.len || xnum) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);

    iolen = 0;

    if (flag0) {
      if (inbuflen < sizeof inbuf) {
        inio = io + iolen++;
        inio->fd = 0;
        inio->events = IOPAUSE_READ;
      }
    }

    for (i = 0;i < xnum;++i) {
      if (x[i].flag_active) {
        x[i].io = io + iolen++;
        dns4_transmit_io(&x[i].dt, x[i].io, &deadline);
      }
    }

    iopause(io, iolen, &deadline, &stamp);

    if (flag0) {
      if (inbuflen < sizeof inbuf) {
        if (inio->revents) {
          r = read(0, inbuf + inbuflen, (sizeof inbuf) - inbuflen);
          if (r <= 0) {
            flag0 = 0;
          }
          else {
            inbuflen += (unsigned int)r;
          }
        }
      }
    }

    for (i = 0; i < xnum; ++i) {
      if (x[i].flag_active) {
        r = dns4_transmit_get(&x[i].dt, x[i].io, &stamp);
        if (r < 0) {
          errout(i);
          x[i].flag_active = 0;
          --numactive;
        }
        else if (r == 1) {
          if (!sa_vector_erase(&name_list)) die_nomem();
          if (dns_name_packet(&name_list, x[i].dt.packet, x[i].dt.packetlen) < 0) {
            errout(i);
          }
          if (name_list.len) {
            if (!stralloc_copy(&x[i].middle, &name_list.va[0])) die_nomem();
            if (!stralloc_cats(&x[i].left, "=")) die_nomem();
          }
          x[i].flag_active = 0;
          --numactive;
        }
      }
    }

    for (;;) {

      if (xnum && !x[0].flag_active) {
        djbio_putsa(djbiofd_out, &x[0].left);
        djbio_putsa(djbiofd_out, &x[0].middle);
        djbio_putsa(djbiofd_out, &x[0].right);
        djbio_flush(djbiofd_out);
        --xnum;
        tmp = x[0];
        for (i = 0; i < xnum; ++i) {
          x[i] = x[i + 1];
        }
        x[xnum] = tmp;
        continue;
      }

      if ((xnum < xmax) && (numactive < maxactive)) {
        i = byte_chr(inbuf, inbuflen, '\n');
        if (inbuflen && (i == inbuflen)) {
          if (!stralloc_catb(&partial, inbuf, inbuflen)) die_nomem();
          inbuflen = 0;
          continue;
        }

        if ((i < inbuflen) || (!flag0 && partial.len)) {
          if (i < inbuflen) {
            ++i;
          }
          if (!stralloc_catb(&partial, inbuf, i)) die_nomem();
          inbuflen -= i;
          for (j = 0; j < inbuflen; ++j) {
            inbuf[j] = inbuf[j + i];
          }

          if (partial.len) {
            i = byte_chr(partial.s, partial.len, '\n');
            i = byte_chr(partial.s, i, '\t');
            i = byte_chr(partial.s, i, ' ');

            if (!stralloc_copyb(&x[xnum].left, partial.s, i)) die_nomem();
            if (!stralloc_erase(&x[xnum].middle)) die_nomem();
            if (!stralloc_copyb(&x[xnum].right, partial.s + i, partial.len - i)) die_nomem();
            x[xnum].flag_active = 0;

            partial.len = i;
            if (!stralloc_0(&partial)) die_nomem();
            if (ip4_scan(&ip, partial.s)) {
              dns_name4_domain(&name, &ip);
              if (dns_resolve_conf_ip4(&servers) < 0) die_read("/etc/resolv.conf");
              if (dns4_transmit_start(&x[xnum].dt, &servers, 1, &name, dns_t_ptr, null_ip4) < 0) {
                errout(xnum);
              }
              else {
                x[xnum].flag_active = 1;
                ++numactive;
              }
            }
            ++xnum;
          }

          partial.len = 0;
          continue;
        }
      }

      break;
    }
  }

  _exit(0);
}
