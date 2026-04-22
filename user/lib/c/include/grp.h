#ifndef __ELK_LIBC_POSIX__GRP_H__
#define __ELK_LIBC_POSIX__GRP_H__

#include <sys/types.h>

struct group
{
    char *gr_name; // The name of the group.
    gid_t gr_gid;  // Numerical group ID.
    char **gr_mem; // Pointer to a null-terminated array of character
                   // pointers to member names.
};

int
initgroups(const char *user, gid_t group);
struct group *getgrgid(gid_t);
struct group *
getgrnam(const char *);
int
getgrgid_r(gid_t, struct group *, char *, size_t, struct group **);
int
getgrnam_r(const char *, struct group *, char *, size_t, struct group **);
struct group *
getgrent(void);
void
endgrent(void);
void
setgrent(void);

#endif
