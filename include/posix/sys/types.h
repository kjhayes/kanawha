#ifndef __ELK_POSIX__SYS_TYPES_H__
#define __ELK_POSIX__SYS_TYPES_H__

// PID
#include <kanawha/process.h>

#include <elk-libc-internal/size_t.h>
#include <elk-libc-internal/ssize_t.h>
#include <elk-libc-internal/off_t.h>

typedef unsigned long blkcnt_t;
typedef unsigned long blksize_t;
typedef unsigned long clock_t;
typedef unsigned long clockid_t;
typedef unsigned long dev_t;
typedef unsigned long fsblkcnt_t;
typedef unsigned long fsfilcnt_t;
typedef unsigned long gid_t;
typedef unsigned long id_t;
typedef unsigned long ino_t;
typedef unsigned long key_t;
typedef unsigned long mode_t;
typedef unsigned long nlink_t;
typedef unsigned long pthread_attr_t;
typedef unsigned long pthread_cond_t;
typedef unsigned long pthread_condattr_t;
typedef unsigned long pthread_key_t;
typedef unsigned long pthread_mutex_t;
typedef unsigned long pthread_mutexattr_t;
typedef unsigned long pthread_once_t;
typedef unsigned long pthread_rwlock_t;
typedef unsigned long pthread_rwlockattr_t;
typedef unsigned long pthread_t;
typedef unsigned long reclen_t;
typedef unsigned long suseconds_t;
typedef unsigned long time_t;
typedef unsigned long timer_t;
typedef unsigned long uid_t;
typedef unsigned long useconds_t;

//dev_t makedev(int maj, int min);
#define makedev(maj, min) (0)
//unsigned int major(dev_t dev);
#define major(dev) (0)
//unsigned int minor(dev_t dev);
#define minor(dev) (0)

#endif
