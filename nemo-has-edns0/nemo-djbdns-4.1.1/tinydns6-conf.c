#include <nemo/exit.h>
#include <nemo/sgetopt.h>

#include "die.h"
#include "auto_prefix.h"
#include "generic-conf.h"

const char USAGE[] = "acct logacct /dir ip";

static char *dir;
static char *user;
static char *log_user;
static char *myip;

static uid_t user_uid;
static gid_t user_gid;

static uid_t log_uid;
static gid_t log_gid;

int main(int argc, char **argv)
{
  PROGRAM = *argv;
  if (argc != 5) die_usage();
  user = argv[1];
  log_user = argv[2];
  dir = argv[3];
  if (dir[0] != '/') die_usage1("dir must start with '/'");
  myip = argv[4];

  get_ids(user, &user_uid, &user_gid);
  get_ids(log_user, &log_uid, &log_gid);

  init(dir);
  make_log(log_user, log_uid, log_gid);

  make_dir("env");
  perm(02755);

  start("env/ROOT");
  outs(dir);
  outs("/root\n");
  finish();
  perm(0644);

  start("env/IP");
  outs(myip);
  outs("\n");
  finish();
  perm(0644);

  start("run");
  outs("#!/bin/sh\n");
  outs("exec 2>&1\n");
  outs("exec envuidgid ");
  outs(user);
  outs(" envdir ./env softlimit -d300000 ");
  outs(auto_prefix);
  outs("/bin/tinydns6\n");
  finish();
  perm(0755);

  make_dir("root");
  perm(02755);

  start("root/data");
  finish();
  perm(0644);

  start("root/add-ns");
  outs("#!/bin/sh\n");
  outs("exec ");
  outs(auto_prefix);
  outs("/bin/tinydns-edit data data.new add ns ${1+\"$@\"}\n");
  finish();
  perm(0755);

  start("root/add-childns");
  outs("#!/bin/sh\n");
  outs("exec ");
  outs(auto_prefix);
  outs("/bin/tinydns-edit data data.new add childns ${1+\"$@\"}\n");
  finish();
  perm(0755);

  start("root/add-host");
  outs("#!/bin/sh\n");
  outs("exec ");
  outs(auto_prefix);
  outs("/bin/tinydns-edit data data.new add host ${1+\"$@\"}\n");
  finish();
  perm(0755);

  start("root/add-alias");
  outs("#!/bin/sh\n");
  outs("exec ");
  outs(auto_prefix);
  outs("/bin/tinydns-edit data data.new add alias ${1+\"$@\"}\n");
  finish();
  perm(0755);

  start("root/add-mx");
  outs("#!/bin/sh\n");
  outs("exec ");
  outs(auto_prefix);
  outs("/bin/tinydns-edit data data.new add mx ${1+\"$@\"}\n");
  finish();
  perm(0755);

  start("root/Makefile");
  outs("data.cdb: data\n");
  outs("\t");
  outs(auto_prefix);
  outs("/bin/tinydns-data\n");
  finish();
  perm(0644);

  _exit(0);
}
