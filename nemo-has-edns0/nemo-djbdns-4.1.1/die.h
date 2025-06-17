#ifndef DIE_H
#define DIE_H

#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/macro_noreturn.h>

extern const char *PROGRAM;
extern const char USAGE[];

void	die1(const char *what) __NORETURN__;

void	die_bind(const char *what) __NORETURN__;
void	die_bogus_query(const char *what) __NORETURN__;
void	die_chdir(const char *dir) __NORETURN__;
void	die_chmod(const char *name) __NORETURN__;
void	die_chroot(const char *dir) __NORETURN__;
void	die_create(const char *fn) __NORETURN__;
void	die_create2(const char *dir, const char *fn) __NORETURN__;
void	die_create_device(const char *dir, const char *device) __NORETURN__;
void	die_env(const char *name) __NORETURN__;
void	die_dns_query(void) __NORETURN__;
void	die_dns_query1(const char *what) __NORETURN__;
void	die_internal(void) __NORETURN__;
void	die_move(const char *from, const char *to) __NORETURN__;
void	die_nomem(void) __NORETURN__;
void    die_not_found(const char *what, const char *value) __NORETURN__;
void	die_open(const char *fn) __NORETURN__;
void	die_parse(const char *name, const char *value) __NORETURN__;
void	die_read(const char *fn) __NORETURN__;
void	die_read_line(unsigned int n) __NORETURN__;
void	die_rr_query(const char *rrtype, const char *query) __NORETURN__;
void	die_servers(void) __NORETURN__;
void	die_setgid(gid_t gid) __NORETURN__;
void	die_setuid(uid_t uid) __NORETURN__;
void	die_stat(const char *fn) __NORETURN__;
void	die_syntax(unsigned int line, const char *why) __NORETURN__;
void	die_sys(const char *what) __NORETURN__;
void	die_unknown_account(const char *account) __NORETURN__;
void	die_usage(void) __NORETURN__;
void	die_usage1(const char *message) __NORETURN__;
void	die_write(const char *fn) __NORETURN__;

void	die_newquery(void) __NORETURN__;
void	die_newioquery(void) __NORETURN__;
void	die_getioquery(void) __NORETURN__;
void	die_newtcpclient(void) __NORETURN__;
void	die_newudpclient(void) __NORETURN__;
void	die_tcpsocket(void) __NORETURN__;
void	die_udpsocket(void) __NORETURN__;

extern const char _FATAL[];

#endif /* DIE_H */
