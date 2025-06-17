#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/strerr.h>
#include <nemo/stralloc.h>
#include <nemo/djbio.h>
#include <nemo/djbiofd.h>
#include <nemo/tai.h>
#include <nemo/taia.h>
#include <nemo/str.h>
#include <nemo/open.h>
#include <nemo/error.h>
#include <nemo/exit.h>
#include <nemo/unix.h>

#include "die.h"
#include "auto_prefix.h"
#include "generic-conf.h"

#include <sys/stat.h>

#include <nemo/hasdevtcp.h>
#ifdef HASDEVTCP
#include <sys/mkdev.h>
#endif

const char INFO[] = "dnscache-conf: ";
const char USAGE[] = "acct logacct /dir [ ip ]";

static char *dir;
static char *user;
static char *log_user;
static const char *myip;

static uid_t user_uid;
static gid_t user_gid;

static uid_t log_uid;
static gid_t log_gid;

#define SEED_SIZE 128

static uint32_t seed[SEED_SIZE];
static unsigned int seedpos = 0;

static void seed_adduint32(uint32_t u)
{
  unsigned int i;

  seed[seedpos] += u;
  if (++seedpos == SEED_SIZE) {
    for (i = 0; i < SEED_SIZE; ++i) {
      u = ((u ^ seed[i]) + 0x9e3779b9) ^ (u << 7) ^ (u >> 25);
      seed[i] = u;
    }
    seedpos = 0;
  }
}

static void seed_addtime(void)
{
  struct taia t;
  byte_t tpack[TAIA_PACK];
  unsigned int i;

  taia_now(&t);
  taia_pack(&t, tpack);
  for (i = 0; i < TAIA_PACK; ++i) {
    seed_adduint32(tpack[i]);
  }
}

int main(int argc, char **argv)
{
  PROGRAM = *argv;
  if (argc < 4) die_usage();

  seed_addtime();
  seed_adduint32((uint32_t)getpid());
  seed_adduint32((uint32_t)getppid());
  seed_adduint32(getuid());
  seed_adduint32(getgid());

  user = argv[1];
  if (!user) die_usage();
  log_user = argv[2];
  if (!log_user) die_usage();
  dir = argv[3];
  if (!dir) die_usage();
  if (dir[0] != '/') die_usage1("dir must start with '/'");
  myip = argv[4];
  if (!myip) myip = "127.0.0.1";

  get_ids(user, &user_uid, &user_gid);
  get_ids(log_user, &log_uid, &log_gid);

  seed_addtime();
  init(dir);
  seed_addtime();
  make_log(log_user, log_uid, log_gid);

  seed_addtime();
  make_dir("env");
  seed_addtime();
  perm(0755);

  seed_addtime();
  start("env/ROOT");
  outs(dir);
  outs("/root\n");
  finish();
  seed_addtime();
  perm(0644);

  seed_addtime();
  start("env/IP");
  outs(myip);
  outs("\n");
  finish();
  seed_addtime();
  perm(0644);

  seed_addtime();
  start("env/IPSEND");
  outs("0.0.0.0\n");
  finish();
  seed_addtime();
  perm(0644);

  seed_addtime();
  start("env/CACHESIZE");
  outs("1000000\n");
  finish();
  seed_addtime();
  perm(0644);

  seed_addtime();
  start("env/DATALIMIT");
  outs("3000000\n");
  finish();
  seed_addtime();
  perm(0644);

  seed_addtime();
  start("env/FDLIMIT");
  outs("250\n");
  finish();
  seed_addtime();
  perm(0644);

  seed_addtime();
  start("run");
  seed_addtime();
  outs("#!/bin/sh\n");
  seed_addtime();
  outs("exec 2>&1\n");
  seed_addtime();
  outs("exec <seed\n");
  seed_addtime();
  outs("exec envdir ./env envuidgid ");
  outs(user);
  seed_addtime();
  outs(" softlimit -O -D ");
  seed_addtime();
  outs(auto_prefix);
  outs("/bin/dnscache\n");
  seed_addtime();
  finish();
  seed_addtime();
  perm(0755);

  seed_addtime();
  make_dir("root");
  seed_addtime();
  perm(0755);

  seed_addtime();
  start("root/ignoreip4");
  finish();
  seed_addtime();
  perm(0600);

  seed_addtime();
  start("root/ignoreip6");
  finish();
  seed_addtime();
  perm(0600);

  seed_addtime();
  make_dir("root/ip");
  seed_addtime();
  perm(0755);

  seed_addtime();
  start("root/ip/127.0.0.1");
  finish();
  seed_addtime();
  perm(0600);

  seed_addtime();
  make_dir("root/servers");
  seed_addtime();
  perm(0755);

  seed_addtime();
  start("root/servers/Makefile");
  seed_addtime();
  outs("data.cdb: data\n");
  outs("\tdnscache-data\n");
  seed_addtime();
  outs("#\n");
  seed_addtime();
  outs("data: @\n");
  outs("\tcat @ | dnscache-iplist2data \".\" > data\n");
  seed_addtime();
  finish();
  seed_addtime();
  perm(0755);

  seed_addtime();
  start("makeroot");
  seed_addtime();
  outs("#!/bin/sh\n");
  seed_addtime();
  outs("dnsip `dnsqr ns . | awk '/answer:/ {print $5;}' | sort` | sed -e 's/ //' > root/servers/@\n");
  seed_addtime();
  finish();
  seed_addtime();
  perm(0755);

  seed_addtime();
  strerr_warn2x(INFO, "root/servers/@ not created, run ./makeroot");
  seed_addtime();
  strerr_warn2x(INFO, "root/servers/data.cdb not created, run \'cd root/servers/ ; make\'");
  seed_addtime();

  start("seed");
  out((char *) seed, 128);
  finish();
  perm(0600);

#ifdef HASDEVTCP
  make_dir("root/etc");
  perm(02755);
  make_dir("root/dev");
  perm(02755);
  start("root/etc/netconfig");
  outs("tcp tpi_cots_ord v inet tcp /dev/tcp -\n");
  outs("udp tpi_clts v inet udp /dev/udp -\n");
  finish();
  perm(0645);
  umask(000);

  if (mknod("root/dev/tcp", S_IFCHR | 0667, makedev(11, 42)) < 0) die_create_device(dir, "root/dev/tcp");
  if (mknod("root/dev/udp", S_IFCHR | 0667, makedev(11, 41)) < 0) die_create_device(dir, "root/dev/udp");
  umask(022);
#endif

  _exit(0);
}
