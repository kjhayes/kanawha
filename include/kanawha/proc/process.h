#ifndef __KANAWHA__PROCESS_H__
#define __KANAWHA__PROCESS_H__

#include <kanawha/thread.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <kanawha/time.h>
#include <kanawha/lock.h>
#include <kanawha/scheduler.h>
#include <kanawha/proc/env.h>
#include <kanawha/usermode.h>
#include <kanawha/waitqueue.h>
#include <kanawha/uapi/process.h>
#include <kanawha/uapi/signal.h>
#include <kanawha/proc/signal.h>

#ifdef CONFIG_PROCFS
#include <kanawha/proc/procfs.h>
#endif

#define PROCESS_LOWMEM_SIZE (1ULL<<32)

#define PROCESS_FLAG_INIT (1ULL<<0)

#define PROCESS_STATUS_SCHEDULED 0
#define PROCESS_STATUS_SUSPEND   1
#define PROCESS_STATUS_ZOMBIE    2

#define INIT_UID (ROOT_UID)
#define INIT_GID ((gid_t)0)

struct process
{
    pid_t id;
    struct ptree_node pid_node;

    // User ID
    uid_t user_id;
    gid_t group_id;

    // Threading
    struct thread_state thread;
    struct scheduler *scheduler;

    // Status
    irq_lock_t status_lock;
    unsigned long flags;
    int exitcode;
    int status;

    // Timestamp
    duration_t creation_timestamp;

    // Waiting on this process to terminate
    struct waitqueue wait_queue;
    // Waiting on any of this processes' children to terminate
    struct waitqueue child_wait_queue;

    // Process Hierarchy
    irq_lock_t hierarchy_lock;
    struct process *parent;
    ilist_node_t child_node;
    ilist_t children;

    // User State
    void __user *user_ip;

    struct signal_state signal_state;

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
    struct fs_path *root_directory;

    // Working Directory
    struct fs_path *working_directory;

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    const char *tracked_exec;
#endif

#ifdef CONFIG_PROCFS
    struct procfs_process_data procfs_data;
#endif
};

struct process *
current_process(void);

int
process_exists(pid_t id);

int
process_id_to_user_id(
        pid_t id,
        uid_t *user_id_out);

int
process_id_to_group_id(
        pid_t id,
        gid_t *group_id_out);

static inline pid_t
process_get_id(
        struct process *process)
{
    return process->id;
}

static inline uid_t
process_get_uid(
        struct process *process)
{
    return process->user_id;
}

static inline gid_t
process_get_gid(
        struct process *process)
{
    return process->group_id;
}

int
process_get_parent_id(
        struct process *proc,
        pid_t *parent_id_out);

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
process_set_root_directory(
        struct process *process,
        struct fs_path *root);

int
process_set_working_directory(
        struct process *process,
        struct fs_path *root);

int
process_write_usermem(
        struct process *process,
        void __user *dst,
        void * src,
        size_t length);

int
process_memset_usermem(
        struct process *process,
        void __user *dst,
        uint8_t val,
        size_t length);

int
process_read_usermem(
        struct process *process,
        void *dst,
        const void __user * src,
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
// If process is not a ZOMBIE, and nowait is non-zero then process_reap returns -EWOULDBLOCK
int
process_reap_child(
        struct process *process,
        pid_t child_id,
        int *exitcode,
        int nowait);

// Find a child of this process which is able to be reaped without waiting,
//
// if nowait is 0, then the process may block until such a child exists.
// if nowait is 1, no such child exists, returns -EWOULDBLOCK
// On success, returns 0, and sets child_out to such a child
int
process_get_reapable_child(
        struct process *process,
        int nowait,
        pid_t *child_id_out);

int
process_clear_forced_ip(
        struct process *process);

static inline int
process_is_root(
        struct process *proc)
{
    return proc->user_id == ROOT_UID;
}

int
process_send_signal(
        pid_t proc_id,
        signal_id_t id,
        unsigned long flags);

int
process_force_awake(
	pid_t proc_id);

// Debugging "Dump" Processes
void
dump_processes(printk_f *printer);

// Allows for architecture specific initialization of a process thread
int arch_on_process_entry(void);

#endif
