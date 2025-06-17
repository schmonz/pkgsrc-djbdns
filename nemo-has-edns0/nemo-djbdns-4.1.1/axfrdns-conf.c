#include <nemo/exit.h>

#include "die.h"
#include "auto_prefix.h"
#include "generic-conf.h"

const char USAGE[] = "acct logacct /dir /tinydns myip";

static char *dir;
static char *user;
static char *log_user;
static char *myip;
static char *tinydns;

static uid_t user_uid;
static gid_t user_gid;

static uid_t log_uid;
static gid_t log_gid;

int main(int argc, char **argv)
{
  PROGRAM = *argv;
  if (argc != 6) die_usage();
  user = argv[1];
  log_user = argv[2];
  dir = argv[3];
  if (dir[0] != '/') die_usage1("dir must start with '/'");
  tinydns = argv[4];
  if (tinydns[0] != '/') die_usage1("tinydns must start with '/'");
  myip = argv[5];

  get_ids(user, &user_uid, &user_gid);
  get_ids(log_user, &log_uid, &log_gid);

  init(dir);
  make_log(log_user, log_uid, log_gid);

  make_dir("env");
  perm(0755);

  start("env/ROOT");
  outs(tinydns);
  outs("/root\n");
  finish();
  perm(0644);

  start("env/IP");
  outs(myip);
  outs("\n");
  finish();
  perm(0644);

  start("env/PORT");
  outs("53\n");
  finish();
  perm(0644);

  start("env/DATALIMIT");
  outs("300000");
  outs("\n");
  finish();
  perm(0644);

  start("run");
  outs("#!/bin/sh\n");
  outs("exec 2>&1\n");
  outs("exec envuidgid ");
  outs(user);
  outs(" envdir ./env softlimit -D");
  outs(" tcpserver -vDRHL -l 0 -x tcp.cdb -- ");
  outs(auto_prefix);
  outs("/bin/axfrdns\n");
  finish();
  perm(0755);

  start("Makefile");
  outs("tcp.cdb: tcp\n");
  outs("\ttcprules tcp.cdb tcp.tmp < tcp\n");
  finish();
  perm(0644);

  start("tcp");
  outs("# sample line:  1.2.3.4:allow, AXFR=\"example.com/3.2.1.in-addr.arpa\"\n");
  outs(":deny\n");
  finish();
  perm(0644);

  _exit(0);
}
