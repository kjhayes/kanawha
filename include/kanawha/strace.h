#ifndef __KANAWHA__STRACE_H__
#define __KANAWHA__STRACE_H__

#include <kanawha/proc/process.h>
#include <kanawha/uapi/syscall.h>

void
strace_begin_syscall(struct process *process, syscall_id_t id);
void
strace_end_syscall(struct process *process, syscall_id_t id);
void
strace_deliver_signal(struct process *process, signal_id_t id);

#endif
