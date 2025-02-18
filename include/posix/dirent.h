#ifndef __ELK_POSIX__DIRENT_H__
#define __ELK_POSIX__DIRENT_H__

#include <sys/types.h>

typedef struct DIR DIR;

struct dirent {
    ino_t  d_ino;       //File serial number.
    char   d_name[];    //Filename string of entry.
};

struct posix_dent {
    ino_t          d_ino;      //File serial number.
    reclen_t       d_reclen;   //Length of this entry, including trailing
                               //padding if necessary. See posix_getdents().
    unsigned char  d_type;     //File type or unknown-file-type indication.
    char           d_name[];   //Filename string of this entry.
};

#define DT_BLK     (1)
#define DT_CHR     (2)
#define DT_DIR     (3)
#define DT_FIFO    (4)
#define DT_LNK     (5)
#define DT_REG     (6)
#define DT_SOCK    (7)
#define DT_UNKNOWN (8)

#define DT_MQ      (0)
#define DT_SEM     (0)
#define DT_SHM     (0)
#define DT_TMO     (0)

int            alphasort(const struct dirent **, const struct dirent **);
int            closedir(DIR *);
int            dirfd(DIR *);
DIR           *fdopendir(int);
DIR           *opendir(const char *);
ssize_t        posix_getdents(int, void *, size_t, int);
struct dirent *readdir(DIR *);
int            readdir_r(DIR *restrict, struct dirent *restrict,
                   struct dirent **restrict);
void           rewinddir(DIR *);
int            scandir(const char *, struct dirent ***,
                   int (*)(const struct dirent *),
                   int (*)(const struct dirent **,
                   const struct dirent **));
void           seekdir(DIR *, long);
long           telldir(DIR *);

#endif
