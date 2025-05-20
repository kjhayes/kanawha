#ifndef __ELK_LIBC_POSIX__MNTENT_H__
#define __ELK_LIBC_POSIX__MNTENT_H__

#include <stdio.h>

struct mntent
{
    char *mnt_fsname;
    char *mnt_dir;
    char *mnt_type;
    char *mnt_opts;
    int mnt_freq;
    int mnt_passno;
};

FILE *setmntent(const char *filename, const char *type);
struct mntent *getmntent(FILE *stream);
int addmntent(FILE *restrict stream,
              const struct mntent *restrict mnt);
int endmntent(FILE *streamp);
char *hasmntopt(const struct mntent *mnt, const char *opt);

#endif
