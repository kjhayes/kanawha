#ifndef __KANAWHA__SYSCALL_H__
#define __KANAWHA__SYSCALL_H__

#include <kanawha/excp.h>
#include <kanawha/usermode.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/ops.h>
#include <kanawha/file.h>
#include <kanawha/uapi/syscall.h>

struct process;

#define DECLARE_SYSCALL_HANDLER_FUNCTIONS(__name, __id, __NAME, __SIG, ...)\
SIG_RETURN_TYPE(__SIG) syscall_ ## __name (struct process *process SIG_ARG_DECLS(__SIG));
SYSCALL_XLIST(DECLARE_SYSCALL_HANDLER_FUNCTIONS)
#undef DECLARE_SYSCALL_HANDLER_FUNCTIONS

void strace_begin_syscall(struct process *process, syscall_id_t id);
void strace_end_syscall(struct process *process, syscall_id_t id);

int syscall_unknown(struct process *process, syscall_id_t id);

const char *
syscall_id_string(syscall_id_t id);

#endif
