#ifndef __KANAWHA__PROC_USER_ACCESS_H__
#define __KANAWHA__PROC_USER_ACCESS_H__

#include <kanawha/proc/process.h>
#include <kanawha/stdint.h>

int
process_user_read(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length);

int
process_user_write(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length);

int
process_user_strlen(
        struct process *process,
        uintptr_t offset,
        size_t max_strlen,
        size_t *strlen);

#endif
