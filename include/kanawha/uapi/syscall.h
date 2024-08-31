#ifndef __KANAWHA__UAPI_SYSCALL_H__
#define __KANAWHA__UAPI_SYSCALL_H__

#include <kanawha/uapi/file.h>

typedef int syscall_id_t;

#define SYSCALL_SIG_EXIT(RET,ARG)\
RET(void)\
ARG(int, exitcode)

#define SYSCALL_SIG_OPEN(RET,ARG)\
RET(fd_t)\
ARG(fd_t, parent)\
ARG(const char __user *, name)\
ARG(size_t, name_len)\
ARG(unsigned long, access_flags)\
ARG(unsigned long, mode_flags)

#define SYSCALL_SIG_CLOSE(RET,ARG)\
RET(int)\
ARG(fd_t, file)

#define SYSCALL_SIG_READ(RET,ARG)\
RET(int)\
ARG(fd_t, file)\
ARG(void __user *, dest)\
ARG(size_t, src_offset)\
ARG(size_t, size)

#define SYSCALL_SIG_WRITE(RET,ARG)\
RET(int)\
ARG(fd_t, file)\
ARG(size_t, dst_offset)\
ARG(void __user *, src)\
ARG(size_t, size)

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

#define SYSCALL_XLIST(X)\
X(exit,   0, EXIT, SYSCALL_SIG_EXIT)\
X(open,   1, OPEN, SYSCALL_SIG_OPEN)\
X(close,  2, CLOSE, SYSCALL_SIG_CLOSE)\
X(read,   3, READ, SYSCALL_SIG_READ)\
X(write,  4, WRITE, SYSCALL_SIG_WRITE)\
X(mmap,   5, MMAP, SYSCALL_SIG_MMAP)\
X(munmap, 6, MUNMAP, SYSCALL_SIG_MUNMAP)\
X(exec,   7, EXEC, SYSCALL_SIG_EXEC)

#define DECLARE_SYSCALL_ID_CONSTANTS(__name, __id, __NAME, ...)\
const static syscall_id_t SYSCALL_ID_ ## __NAME = __id;
SYSCALL_XLIST(DECLARE_SYSCALL_ID_CONSTANTS)
#undef DECLARE_SYSCALL_ID_CONSTANTS

#ifndef __KANAWHA_SYSCALL_KEEP_XLIST
#undef SYSCALL_SIG_EXIT
#undef SYSCALL_SIG_OPEN
#undef SYSCALL_SIG_CLOSE
#undef SYSCALL_SIG_READ
#undef SYSCALL_SIG_WRITE
#undef SYSCALL_SIG_MMAP
#undef SYSCALL_SIG_MUNMAP
#undef SYSCALL_SIG_EXEC
#undef SYSCALL_XLIST
#endif

#endif
