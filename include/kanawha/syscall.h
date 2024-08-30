#ifndef __KANAWHA__SYSCALL_H__
#define __KANAWHA__SYSCALL_H__

#include <kanawha/excp.h>
#include <kanawha/usermode.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/ops.h>
#include <kanawha/file.h>

struct process;
typedef size_t syscall_id_t;

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
ARG(void __user **, where)\
ARG(size_t, size)\
ARG(unsigned long, access_flags)\
ARG(unsigned long, mmap_flags)\

// TODO: munmap

#define SYSCALL_XLIST(X)\
X(exit,   0, EXIT, SYSCALL_SIG_EXIT)\
X(open,   1, OPEN, SYSCALL_SIG_OPEN)\
X(close,  3, CLOSE, SYSCALL_SIG_CLOSE)\
X(read,   4, READ, SYSCALL_SIG_READ)\
X(write,  5, WRITE, SYSCALL_SIG_WRITE)\
X(mmap,   6, MMAP, SYSCALL_SIG_MMAP)

#define DECLARE_SYSCALL_ID_CONSTANTS(__name, __id, __NAME, ...)\
const static syscall_id_t SYSCALL_ID_ ## __NAME = __id;
SYSCALL_XLIST(DECLARE_SYSCALL_ID_CONSTANTS)
#undef DECLARE_SYSCALL_ID_CONSTANTS

#define DECLARE_SYSCALL_HANDLER_FUNCTIONS(__name, __id, __NAME, __SIG, ...)\
SIG_RETURN_TYPE(__SIG) syscall_ ## __name (struct process *process SIG_ARG_DECLS(__SIG));
SYSCALL_XLIST(DECLARE_SYSCALL_HANDLER_FUNCTIONS)
#undef DECLARE_SYSCALL_HANDLER_FUNCTIONS

#undef SYSCALL_SIG_EXIT
#undef SYSCALL_XLIST

int syscall_unknown(struct process *process, syscall_id_t id);

#endif
