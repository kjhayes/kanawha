#ifndef __KANAWHA__UAPI_SYSCALL_H__
#define __KANAWHA__UAPI_SYSCALL_H__

#include <kanawha/uapi/file.h>
#include <kanawha/uapi/process.h>

typedef int syscall_id_t;

#define SYSCALL_SIG_EXIT(RET,ARG)\
RET(void)\
ARG(int, exitcode)

#define SYSCALL_SIG_OPEN(RET,ARG)\
RET(int)\
ARG(const char __user *, path)\
ARG(unsigned long, access_flags)\
ARG(unsigned long, mode_flags)\
ARG(fd_t __user *, fd)

#define SYSCALL_SIG_CLOSE(RET,ARG)\
RET(int)\
ARG(fd_t, file)

#define SYSCALL_SIG_READ(RET,ARG)\
RET(ssize_t)\
ARG(fd_t, file)\
ARG(void __user *, dest)\
ARG(size_t, size)

#define SYSCALL_SIG_WRITE(RET,ARG)\
RET(ssize_t)\
ARG(fd_t, file)\
ARG(void __user *, src)\
ARG(size_t, size)

#define SYSCALL_SIG_SEEK(RET,ARG)\
RET(ssize_t)\
ARG(fd_t, file)\
ARG(ssize_t, offset)\
ARG(int, whence)

#define SYSCALL_SIG_ATTR(RET,ARG)\
RET(int)\
ARG(fd_t, file)\
ARG(int, attr)\
ARG(size_t __user *, value)

#define SYSCALL_SIG_MMAP(RET,ARG)\
RET(int)\
ARG(fd_t, file)\
ARG(size_t, file_offset)\
ARG(void __user *, where)\
ARG(size_t, size)\
ARG(unsigned long, prot_flags)\
ARG(unsigned long, mmap_flags)\

#define SYSCALL_SIG_MUNMAP(RET,ARG)\
RET(int)\
ARG(void __user *, mapping)

#define SYSCALL_SIG_EXEC(RET,ARG)\
RET(int)\
ARG(fd_t, file)\
ARG(unsigned long, exec_flags)

#define SYSCALL_SIG_ENVIRON(RET,ARG)\
RET(int)\
ARG(const char __user *, key)\
ARG(char __user *, value)\
ARG(size_t, len)\
ARG(int, operation)

#define SYSCALL_SIG_CHILDNAME(RET,ARG)\
RET(int)\
ARG(fd_t, parent)\
ARG(size_t, child_index)\
ARG(char __user *, buf)\
ARG(size_t, buf_size)

#define SYSCALL_SIG_SPAWN(RET,ARG)\
RET(int)\
ARG(void __user *, func)\
ARG(void *, arg)\
ARG(unsigned long, flags)\
ARG(pid_t __user *, child)

#define SYSCALL_SIG_REAP(RET,ARG)\
RET(int)\
ARG(pid_t, id)\
ARG(unsigned long, flags)\
ARG(int __user *, exitcode)

#define SYSCALL_SIG_GETPID(RET,ARG)\
RET(pid_t)

#define SYSCALL_SIG_MOUNT(RET,ARG)\
RET(int)\
ARG(const char __user *, source)\
ARG(fd_t, dest_dir)\
ARG(const char __user *, dest_name)\
ARG(const char __user *, fs_type)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_UNMOUNT(RET,ARG)\
RET(int)\
ARG(fd_t, mntpoint)

#define SYSCALL_XLIST(X)\
X(exit,      0,  EXIT,       SYSCALL_SIG_EXIT)\
X(open,      1,  OPEN,       SYSCALL_SIG_OPEN)\
X(close,     2,  CLOSE,      SYSCALL_SIG_CLOSE)\
X(read,      3,  READ,       SYSCALL_SIG_READ)\
X(write,     4,  WRITE,      SYSCALL_SIG_WRITE)\
X(seek,      5,  SEEK,       SYSCALL_SIG_SEEK)\
X(attr,      6,  ATTR,       SYSCALL_SIG_ATTR)\
X(mmap,      7,  MMAP,       SYSCALL_SIG_MMAP)\
X(munmap,    8,  MUNMAP,     SYSCALL_SIG_MUNMAP)\
X(exec,      9,  EXEC,       SYSCALL_SIG_EXEC)\
X(environ,   10, ENVIRON,    SYSCALL_SIG_ENVIRON)\
X(childname, 11, CHILDNAME,  SYSCALL_SIG_CHILDNAME)\
X(spawn,     12, SPAWN,      SYSCALL_SIG_SPAWN)\
X(reap,      13, REAP,       SYSCALL_SIG_REAP)\
X(getpid,    14, GETPID,     SYSCALL_SIG_GETPID)\
X(mount,     15, MOUNT,      SYSCALL_SIG_MOUNT)\
X(unmount,   16, UNMOUNT,    SYSCALL_SIG_UNMOUNT)

#define DECLARE_SYSCALL_ID_CONSTANTS(__name, __id, __NAME, ...)\
const static syscall_id_t SYSCALL_ID_ ## __NAME = __id;
SYSCALL_XLIST(DECLARE_SYSCALL_ID_CONSTANTS)
#undef DECLARE_SYSCALL_ID_CONSTANTS

#ifdef KANAWHA_SYSCALL_UNDEF_XLISTS
#undef SYSCALL_SIG_EXIT
#undef SYSCALL_SIG_OPEN
#undef SYSCALL_SIG_CLOSE
#undef SYSCALL_SIG_READ
#undef SYSCALL_SIG_WRITE
#undef SYSCALL_SIG_MMAP
#undef SYSCALL_SIG_MUNMAP
#undef SYSCALL_SIG_EXEC
#undef SYSCALL_SIG_ENVIRON
#undef SYSCALL_XLIST
#endif

#endif
