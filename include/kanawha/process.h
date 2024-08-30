#ifndef __KANAWHA__PROCESS_H__
#define __KANAWHA__PROCESS_H__

#include <kanawha/thread.h>
#include <kanawha/stdint.h>
#include <kanawha/vmem.h>
#include <kanawha/scheduler.h>
#include <kanawha/file.h>
#include <kanawha/usermode.h>
#include <kanawha/syscall/mmap.h>

typedef uintptr_t process_id_t;

#define PROCESS_FLAG_INIT (1ULL<<0)

#define PROCESS_STATUS_SCHEDULED 0
#define PROCESS_STATUS_SUSPEND   1
#define PROCESS_STATUS_ZOMBIE    2

struct process
{
    process_id_t id;
    struct ptree_node pid_node;

    // Threading
    struct thread_state thread;
    struct scheduler *scheduler;

    struct mmap mmap;
    struct vmem_region_ref *mmap_ref;

    // Status
    spinlock_t status_lock;
    unsigned long flags;
    int exitcode;
    int status;

    // Process Hierarchy
    spinlock_t hierarchy_lock;
    struct process *parent;
    ilist_node_t child_node;
    ilist_t children;

    // File Descriptor Table
    struct file_table file_table;
};

struct process *
current_process(void);

int
process_schedule(
        struct process *process);

int
process_suspend(
        struct process *process);

int
process_set_scheduler(
        struct process *process,
        struct scheduler *sched);

int
process_write_usermem(
        struct process *process,
        void __user *dst,
        void * src,
        size_t length);

int
process_read_usermem(
        struct process *process,
        void *dst,
        void __user * src,
        size_t length);

// Terminate the process without signalling
int
process_terminate(
        struct process *process,
        int exitcode);

#endif
