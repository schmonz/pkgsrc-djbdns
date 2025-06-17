#include <nemo/stdint.h>
#include <nemo/unixtypes.h>

#include <nemo/open.h>
#include <nemo/unix.h>

#include "generic-conf.h"
#include "die.h"

#include <sys/stat.h>
#include <pwd.h>

static const char *dir;
static const char *fn;

static int fd;
static char buf[1024];
static djbio io;

void init(const char *d)
{
  dir = d;
  umask(022);
  if (mkdir(dir, 0700) < 0) die_create(dir);
  if (chmod(dir, 0755) < 0) die_chmod(dir);
  if (chdir(dir) < 0) die_chdir(dir);
}

void fail(void)
{
  die_create2(dir, fn);
}

void make_dir(const char *s)
{
  fn = s;
  if (mkdir(fn, 0700) < 0) fail();
}

void start(const char *s)
{
  fn = s;
  fd = open_trunc(fn);
  if (fd < 0) fail();
  djbio_initwrite(&io, write, fd, buf, sizeof buf);
}

void outsa(const stralloc *sa)
{
  if (djbio_putsa(&io, sa) < 0) fail();
}

void outs(const char *s)
{
  if (djbio_puts(&io, s) < 0) fail();
}

void out(const char *s, unsigned int len)
{
  if (djbio_put(&io, s, len) < 0) fail();
}

void copy_from(djbio *b)
{
  if (djbio_copy(&io, b) < 0) fail();
}

void finish(void)
{
  if (djbio_flush(&io) < 0) fail();
  if (fsync(fd) < 0) fail();
  close(fd);
}

void perm(mode_t mode)
{
  if (chmod(fn, mode) < 0) fail();
}

void owner(uid_t uid, gid_t gid)
{
  if (chown(fn, uid, gid) < 0) fail();
}

void make_log(const char *user, uid_t uid, gid_t gid)
{
  make_dir("log");
  perm(0755);

  make_dir("log/main");
  owner(uid, gid);
  perm(0755);

  start("log/status");
  finish();
  owner(uid, gid);
  perm(0644);

  start("log/run");
  outs("#!/bin/sh\n");
  outs("exec setuidgid ");
  outs(user);
  outs(" multilog t ./main\n");
  finish();
  perm(0755);
}

void get_ids(const char *user, uid_t *uid, gid_t *gid)
{
  struct passwd *pw;

  pw = getpwnam(user);
  if (!pw) die_unknown_account(user);
  *uid = pw->pw_uid;
  *gid = pw->pw_gid;
}
