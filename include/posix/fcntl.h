#ifndef __ELK_POSIX__FCNTL_H__
#define __ELK_POSIX__FCNTL_H__

#include <sys/types.h>

// cmd Values

enum {
  F_DUPFD = 1,
  F_GETFD,
  F_SETFD,
  F_GETFL,
  F_SETFL,
  F_GETLK,
  F_SETLK,
  F_SETLKW,
  F_GETOWN,
  F_SETOWN,
};

#define FD_CLOEXEC (0)

#define F_RDLCK (0)
#define F_UNLCK (1)
#define F_WRLCK (2)

#include <stdio.h>

// open oflags
#define O_CLOEXEC   (1ULL<<0)
#define O_CREAT     (1ULL<<1)
#define O_DIRECTORY (1ULL<<2)
#define O_EXCL      (1ULL<<3)
#define O_NOCTTY    (1ULL<<4)
#define O_NOFOLLOW  (1ULL<<5)
#define O_TRUNC     (1ULL<<6)
#define O_TTY_INIT  (1ULL<<7)

// open status flags
#define O_APPEND    (1ULL<<0)
#define O_DSYNC     (1ULL<<1)
#define O_NONBLOCK  (1ULL<<2)
#define O_RSYNC     (1ULL<<3)
#define O_SYNC      (1ULL<<4)

// open access modes
#define O_ACCMODE (~((1ULL<<5)-1))
#define O_EXEC    (1ULL<<5)
#define O_RDONLY  (1ULL<<6)
#define O_RDWR    (1ULL<<7)
#define O_SEARCH  (1ULL<<8)
#define O_WRONLY  (1ULL<<9)

#include <sys/stat.h>

// faccessat Related Macros
#define AT_EACCESS 1

// fstatat Related Macros
#define AT_SYMLINK_NOFOLLOW 1

// linkat Related Macros
#define AT_SYMLINK_FOLLOW 1

// unlinkat Related Macros
#define AT_REMOVEDIR 1

struct flock {
    short  l_type;   // Type of lock; F_RDLCK, F_WRLCK, F_UNLCK. 
    short  l_whence; // Flag for starting offset. 
    off_t  l_start;  // Relative offset in bytes. 
    off_t  l_len;    // Size; if 0 then until EOF. 
    pid_t  l_pid;    // Process ID of the process holding the lock; returned with F_GETLK.
};

int  creat(const char *, mode_t);
int  fcntl(int, int, ...);
int  open(const char *, int, ...);
int  posix_fadvise(int, off_t, off_t, int);
int  posix_fallocate(int, off_t, off_t);

#endif
