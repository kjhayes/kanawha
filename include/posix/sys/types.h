#ifndef __ELK_POSIX__SYS_TYPES_H__
#define __ELK_POSIX__SYS_TYPES_H__

// PID
#include <kanawha/process.h>

typedef unsigned long size_t;
typedef __INTPTR_TYPE__ ssize_t;

typedef int blkcnt_t;
typedef int blksize_t;
typedef int clock_t;
typedef int clockid_t;
typedef int dev_t;
typedef int fsblkcnt_t;
typedef int fsfilcnt_t;
typedef int gid_t;
typedef int id_t;
typedef int ino_t;
typedef int key_t;
typedef int mode_t;
typedef int nlink_t;
typedef int off_t;
typedef int pthread_attr_t;
typedef int pthread_cond_t;
typedef int pthread_condattr_t;
typedef int pthread_key_t;
typedef int pthread_mutex_t;
typedef int pthread_mutexattr_t;
typedef int pthread_once_t;
typedef int pthread_rwlock_t;
typedef int pthread_rwlockattr_t;
typedef int pthread_t;
typedef int reclen_t;
typedef int suseconds_t;
typedef int time_t;
typedef int timer_t;
typedef int uid_t;
typedef int useconds_t;

#endif
