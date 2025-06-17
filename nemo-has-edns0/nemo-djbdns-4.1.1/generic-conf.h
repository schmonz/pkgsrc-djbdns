#ifndef NEMO_GENERIC_CONF_H
#define NEMO_GENERIC_CONF_H

#include <nemo/stdint.h>
#include <nemo/djbio.h>

void init(const char *dir);

void make_dir(const char *dname);

void start(const char *fn);
void outsa(const stralloc *sa);
void outs(const char *s);
void out(const char *s, unsigned int len);
void copy_from(djbio *ssio);
void finish(void);
void fail(void);

void perm(mode_t mode);
void owner(uid_t uid, gid_t gid);
void make_log(const char *user, uid_t uid, gid_t gid);

void get_ids(const char *user, uid_t *uid, gid_t *gid);

#endif
