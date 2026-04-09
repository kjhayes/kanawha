#ifndef __ELK_LIBC_POSIX__PWD_H__
#define __ELK_LIBC_POSIX__PWD_H__

#include <sys/types.h>

struct passwd
{
    char    *pw_name;   // user's login name
    uid_t    pw_uid;    // numerical user ID
    gid_t    pw_gid;    // numerical group ID
    char    *pw_dir;    // initial working directory
    char    *pw_shell;  // program to use as shell
    char    *pw_passwd; // hashed password
    char    *pw_gecos;  // real name
};

struct passwd *getpwnam(const char *);
struct passwd *getpwuid(uid_t);
int            getpwnam_r(const char *, struct passwd *, char *,
                   size_t, struct passwd **);
int            getpwuid_r(uid_t, struct passwd *, char *,
                   size_t, struct passwd **);
void           endpwent(void);
struct passwd *getpwent(void);
void           setpwent(void);

#endif
