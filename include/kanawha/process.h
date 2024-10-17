#ifndef __KANAWHA__PROCESS_H__
#define __KANAWHA__PROCESS_H__

#include <kanawha/thread.h>
#include <kanawha/stdint.h>
#include <kanawha/vmem.h>
#include <kanawha/scheduler.h>
#include <kanawha/env.h>
#include <kanawha/usermode.h>
#include <kanawha/waitqueue.h>
#include <kanawha/uapi/process.h>

#define PROCESS_LOWMEM_SIZE (1ULL<<32)

#define PROCESS_FLAG_INIT (1ULL<<0)

#define PROCESS_STATUS_SCHEDULED 0
#define PROCESS_STATUS_SUSPEND   1
#define PROCESS_STATUS_ZOMBIE    2

struct process
{
    pid_t id;
    struct ptree_node pid_node;

    // Threading
    struct thread_state thread;
    struct scheduler *scheduler;

    // Status
    spinlock_t status_lock;
    unsigned long flags;
    int exitcode;
    int status;

    struct waitqueue wait_queue;

    // Process Hierarchy
    spinlock_t hierarchy_lock;
    struct process *parent;
    ilist_node_t child_node;
    ilist_t children;

    spinlock_t signal_lock;
    int forcing_ip;
    void __user *forced_ip;

    // Virtual Memory
    struct mmap *mmap;
    struct vmem_region_ref *mmap_ref;
    ilist_node_t mmap_list_node;

    // File Descriptor Table
    struct file_table* file_table;
    ilist_node_t file_table_node;

    // Environment Variables
    struct environment *environ;
    ilist_node_t environ_node;

    // Root Directory
    struct fs_path *root;
};

struct process *
current_process(void);

struct process *
process_from_pid(
        pid_t id);

struct process *
process_spawn_child(
        struct process *parent,
        void __user *entry,
        void *arg,
        unsigned long spawn_flags);

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
process_set_root(
        struct process *process,
        struct fs_path *root);

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

int
process_strlen_usermem(
        struct process *process,
        const char __user *str,
        size_t max_len,
        size_t *len);


// Terminate the process without signalling,
// if process==current_process() then IRQ's
// will be disabled on return so that we will
// not be preempted before we can call thread_abandon
int
process_terminate(
        struct process *process,
        int exitcode);

// De-allocate a process and get the exitcode
//
// Returns 0, populates exitcode, and invalidates the process pointer on success,
// else Returns a negative errno, exitcode is undefined, and process should still be valid
//
// If process is not a ZOMBIE, then process_reap will return -EINVAL
int
process_reap(
        struct process *process,
        int *exitcode);

int
process_force_ip(
        struct process *process,
        void __user *ip);

int
process_clear_forced_ip(
        struct process *process);

#endif
