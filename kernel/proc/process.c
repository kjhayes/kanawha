
#include <kanawha/proc/process.h>
#include <kanawha/irq.h>
#include <kanawha/thread.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <kanawha/init.h>
#include <kanawha/usermode.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/ramfile.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/stddef.h>
#include <kanawha/timer.h>
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/assert.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/uapi/spawn.h>

static DECLARE_SPINLOCK(process_pid_lock);
static DECLARE_PTREE(process_pid_tree);

static struct process *init_process = NULL;

void
dump_process(
        printk_f *printer,
        struct process *proc)
{
    (*printer)(
            "\tPROCESS(%ld) (sched=%s) %s%s"
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
            "(exec=%s)"
#endif 
            "%s\n"
            ,

            proc->id,

            proc->scheduler == NULL ? "NONE" :
            proc->scheduler->name == NULL ? "UNNAMED" :
            proc->scheduler->name,

            proc->status == PROCESS_STATUS_SUSPEND ? "[SUSPEND]" :
            proc->status == PROCESS_STATUS_SCHEDULED ? "[SCHEDULED]" :
            proc->status == PROCESS_STATUS_ZOMBIE ? "[ZOMBIE]" : "[INVALID-PROCESS-STATUS]",

            proc->thread.status == THREAD_STATUS_READY ? "[READY]" :
            proc->thread.status == THREAD_STATUS_TIRED ? "[TIRED]" :
            proc->thread.status == THREAD_STATUS_RUNNING ? "[RUNNING]" :
            proc->thread.status == THREAD_STATUS_SLEEPING ? "[SLEEPING]" :
            proc->thread.status == THREAD_STATUS_ABANDONED ? "[ABANDONED]" :
            proc->thread.status == THREAD_STATUS_PREPARING ? "[PREPARING]" :
            proc->thread.status == THREAD_STATUS_SCHEDULED ? "[SCHEDULED]" : "[INVALID-THREAD-STATUS]",

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
            proc->tracked_exec != NULL ? proc->tracked_exec : "NULL",
#endif
            ""
            );
//    mmap_dump(printer, proc->mmap);
}

void
dump_processes(printk_f *printer) {
    spin_lock(&process_pid_lock);
    struct ptree_node *node;
    node = ptree_get_first(&process_pid_tree);
    (*printer)("--- Process Table ---\n");
    while(node) {
        struct process *proc = container_of(node, struct process, pid_node);
        dump_process(printer, proc);
        node = ptree_get_next(node);
    }
    spin_unlock(&process_pid_lock);
}

static inline struct process *
__process_from_pid_lockless(pid_t id)
{
    struct process *proc;

    struct ptree_node *node =
        ptree_get(&process_pid_tree, id);
    if(node == NULL) {
        return NULL;
    }

    proc = container_of(node, struct process, pid_node);
    return proc;
}

int
process_exists(pid_t id)
{
    int irq_flags = spin_lock_irq_save(&process_pid_lock);
    struct ptree_node *node =
        ptree_get(&process_pid_tree, id);
    if(node == NULL) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        return 0;
    }
    spin_unlock_irq_restore(&process_pid_lock, irq_flags);
    return 1;
}

int
process_id_to_user_id(
        pid_t id,
        uid_t *uid)
{
    int irq_flags = spin_lock_irq_save(&process_pid_lock);

    struct ptree_node *node =
        ptree_get(&process_pid_tree, id);
    if(node == NULL) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        return -ENXIO;
    }

    struct process *proc =
        container_of(node, struct process, pid_node);

    DEBUG_ASSERT(KERNEL_ADDR(proc));

    *uid = proc->user_id;

    spin_unlock_irq_restore(&process_pid_lock, irq_flags);

    return 0;
}

int
process_id_to_group_id(
        pid_t id,
        uid_t *gid)
{
    int irq_flags = spin_lock_irq_save(&process_pid_lock);

    struct ptree_node *node =
        ptree_get(&process_pid_tree, id);
    if(node == NULL) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        return -ENXIO;
    }

    struct process *proc =
        container_of(node, struct process, pid_node);

    DEBUG_ASSERT(KERNEL_ADDR(proc));

    *gid = proc->group_id;

    spin_unlock_irq_restore(&process_pid_lock, irq_flags);

    return 0;
}

int
process_get_parent_id(
        struct process *proc,
        pid_t *pid_out)
{
    int res;

    pid_t parent_id = proc->id;

    int irq_flags = spin_lock_irq_save(&proc->hierarchy_lock);

    if(proc->parent != NULL) {
        parent_id = proc->parent->id;
    }

    spin_unlock_irq_restore(&proc->hierarchy_lock, irq_flags);

    *pid_out = parent_id;

    return 0;
}

static int
process_assign_pid(
        struct process *process)
{
    int irq_flags = spin_lock_irq_save(&process_pid_lock);

    int res;
    res = ptree_insert_any(&process_pid_tree, &process->pid_node);
    if(res) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        return res;
    }

    process->id = process->pid_node.key;

    spin_unlock_irq_restore(&process_pid_lock, irq_flags);
    return 0;
}

static int
__process_remove_pid_lockless(
        struct process *process)
{
    struct ptree_node *removed;
    removed = ptree_remove(&process_pid_tree, process->id);

    DEBUG_ASSERT(removed == &process->pid_node);
    return 0;
}
static int
__process_remove_pid(
        struct process *process)
{
    int res;
    int irq_flags = spin_lock_irq_save(&process_pid_lock);
    res = __process_remove_pid_lockless(process);
    spin_unlock_irq_restore(&process_pid_lock, irq_flags);
    return res;

}

struct process *
current_process(void)
{
    struct thread_state *thread = current_thread();
    if(thread == NULL) {
        // We haven't even started threading yet
        return NULL;
    }

    if(thread->flags & THREAD_FLAG_PROCESS) {
        return container_of(thread, struct process, thread);
    }

    // This is a purely kernel thread, no associated process
    return NULL;
}

static void
init_process_kernel_entry(void *in)
{
    int res;

    struct process *process = current_process();
    DEBUG_ASSERT(process != NULL);

    const char *binary_path = CONFIG_INIT_PROCESS_PATH;

    res = environment_set(process->environ, "ARGV", CONFIG_INIT_PROCESS_PATH " " CONFIG_INIT_PROCESS_ARGS);
    if(res) {
        panic("Failed to set init process ARGV! (err=%s)\n",
                errnostr(res));
    }

    fd_t binary_fd;
    res = file_table_open(
            process->file_table,
            process,
            binary_path,
            FILE_PERM_READ|FILE_PERM_EXEC,
            0,
            &binary_fd); 
    if(res) {
        panic("Failed to find init process binary with path \"%s\" (err=%s)\n",
                binary_path, errnostr(res));
    }

    enable_irqs();

    res = syscall_exec(
            process,
            binary_fd,
            0);
    if(res) {
        panic("Failed to exec the init process file \"%s\"! (err=%s)\n",
                binary_path, errnostr(res));
    }

    disable_irqs();

    dprintk("init_process_kernel_entry(%p)\n",
            NULL);

    enter_usermode(NULL);

    panic("enter_usermode Returned!\n");
}

struct spawned_process_state {
    void __user *entry;
    void *arg;
};

static void
spawned_process_kernel_entry(void *in)
{
    int res;

    struct spawned_process_state *state = in;

    struct process *process = current_process();
    DEBUG_ASSERT(process);

    void __user *entry = state->entry;
    void *arg = state->arg;

    kfree(state);

    dprintk("spawned_process_kernel_entry(%p,%p)\n",
            entry, arg);

    process->user_ip = entry;

    enter_usermode(arg);
}

static struct process *
process_alloc(
        thread_f *kernel_entry,
        void *kernel_in,
        unsigned long flags,
        struct process *parent)
{
    int res;

    struct process *process = kmalloc(sizeof(struct process));
    if(process == NULL) {
        eprintk("process_alloc: Out of Memory!\n");
        goto err0;
    }
    memset(process, 0, sizeof(struct process));

    spinlock_init(&process->ref_lock);
    process->refs = 0;

    spinlock_init(&process->status_lock);
    spinlock_init(&process->hierarchy_lock);
    ilist_init(&process->children);
    waitqueue_init(&process->wait_queue);
    waitqueue_init(&process->child_wait_queue);

    process->creation_timestamp = current_timestamp();

    process->root_directory = NULL;
    process->working_directory = NULL;
    process->mmap = NULL;
    process->file_table = NULL;
    process->environ = NULL;

    res = signal_state_init(&process->signal_state);
    if(res) {
        eprintk("process_alloc: Failed to initialize process signal state!\n");
        goto err0;
    }

    res = thread_init(
            &process->thread,
            kernel_entry,
            kernel_in,
            THREAD_FLAG_PROCESS);

    if(res) {
        eprintk("process_alloc: thread_init returned (%s)\n",
                errnostr(res));
        goto err1;
    }

    process->parent = parent;
    if(parent != NULL) {
        spin_lock(&parent->hierarchy_lock);
        ilist_push_tail(&parent->children, &process->child_node);
        process->user_id = parent->user_id;
        process->group_id = parent->group_id;
        spin_unlock(&parent->hierarchy_lock);
    } else {
        DEBUG_ASSERT(flags & PROCESS_FLAG_INIT);
        process->user_id = INIT_UID;
        process->group_id = INIT_GID;
    }

    res = process_assign_pid(process);
    if(res) {
        eprintk("process_alloc: process_assign_pid returned (%s)\n",
                errnostr(res));
        goto err2;
    } 

    process->flags = flags;
    process->status = PROCESS_STATUS_SUSPEND;

    dprintk("allocated process(%ld) thread(%ld)\n", process->id, process->thread.id);

    return process;

err3:
    __process_remove_pid(process);
err2:
    thread_deinit(&process->thread);
err1:
    kfree(process);
err0:
    return NULL;
}

static int
process_free(struct process *process)
{
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    if(process->tracked_exec) {
        kfree((void*)process->tracked_exec);
    }
#endif

    thread_deinit(&process->thread);
    kfree(process);

    return 0;
}

static int
launch_init_process(void)
{
    int res;

    DEBUG_ASSERT_MSG(irqs_enabled(), "Running launch_init_process with interrupts disabled!");

    if(init_process != NULL) {
        panic("launch_init_process: init_process is not NULL!\n");
    }

    struct process *process = process_alloc(
            init_process_kernel_entry,
            NULL,
            PROCESS_FLAG_INIT, // Flags
            NULL // Parent
            );
    if(process == NULL) {
        panic("Failed to alloc init process!\n");
    }

    const char *fs_name = CONFIG_INITIAL_FS_FILESYSTEM;

    struct fs_type *type =
        fs_type_find(fs_name);
    if(type == NULL) {
        eprintk("Cannot find root fs filesystem type \"%s\"\n",
                fs_name);
        return -ENXIO;
    }

    struct fs_mount *sysfs_mount = sysfs_mount_find(CONFIG_INITIAL_FS_BACKEND_SYSFS_DIR);
    if(sysfs_mount == NULL) {
        eprintk("Cannot find initial filesystem backing sysfs \"%s\"!\n",
                CONFIG_INITIAL_FS_BACKEND_SYSFS_DIR);
        return -ENXIO;
    }

    size_t sysfs_root_index;
    res = fs_mount_root_index(sysfs_mount, &sysfs_root_index);
    if(res) {
        eprintk("Failed to get root index of initial filesystem backing sysfs!\n");
        return res;
    }


    struct fs_node *sysfs_root = fs_mount_get_node(sysfs_mount, sysfs_root_index);
    if(sysfs_root == NULL) {
        eprintk("Cannot get initial filesystem sysfs root node \"%s\"!\n",
                CONFIG_INITIAL_FS_BACKEND_SYSFS_DIR);
        return -EINVAL;
    }

    size_t sysfs_file_index;
    res = fs_node_lookup(sysfs_root, CONFIG_INITIAL_FS_BACKEND_FILE_NAME, &sysfs_file_index);
    fs_mount_put_node(sysfs_mount, sysfs_root);
    if(res) {
        eprintk("Failed to lookup initial filesystem backing file \"%s\"!\n",
                CONFIG_INITIAL_FS_BACKEND_FILE_NAME);
        return res;
    }

    struct fs_node *backing_node = fs_mount_get_node(sysfs_mount, sysfs_file_index);
    if(backing_node == NULL) {
        eprintk("Failed to get initial filesystem backing file \"%s\"!\n",
                CONFIG_INITIAL_FS_BACKEND_FILE_NAME);
        return -EINVAL;
    }

    struct fs_mount *root_fs_mnt;
    res = fs_type_mount_file(
            type,
            backing_node,
            &root_fs_mnt);

    fs_node_put(backing_node);

    if(res) {
        return res;
    }

    struct fs_path *root;
    res = fs_path_mount_root(root_fs_mnt, &root);
    if(res) {
        process_free(process);
        return res;
    }

    res = process_set_root_directory(process, root);
    if(res) {
        eprintk("Failed to set init process root directory! (err=%s)\n",
                errnostr(res));
        process_free(process);
        return res;
    }

    res = process_set_working_directory(process, root);
    if(res) {
        eprintk("Failed to set init process working directory! (err=%s)\n",
                errnostr(res));
        process_free(process);
        return res;
    }

    res = mmap_create(PROCESS_LOWMEM_SIZE, process);
    if(process->mmap == NULL) {
        process_free(process);
        return res;
    }

    res = file_table_create(process);
    if(res) {
        eprintk("Failed to create init process file_table!\n",
                errnostr(res));
        process_free(process);
        return res;
    }

    res = environment_create(process);
    if(res) {
        process_free(process);
        return res;
    }

    init_process = process;

    dprintk("Created init Process (pid=%ld)\n",
            (sl_t)process->id);

    struct scheduler *sched = current_sched();
    if(sched == NULL) {
        eprintk("Could not find a scheduler on CPU (%ld)!\n",
                (sl_t)current_cpu_id());
        mmap_deattach(process->mmap, process);
        kfree(process);
        return -EINVAL;
    }

    res = process_set_scheduler(process, sched);
    if(res) {
        eprintk("Failed to set init process scheduler! (err=%s)\n",
                errnostr(res));
        mmap_deattach(process->mmap, process);
        kfree(process);
        return res;
    }

    res = process_schedule(process);
    if(res) {
        eprintk("Failed to schedule init process! (err=%s)\n",
                errnostr(res));
        mmap_deattach(process->mmap, process);
        kfree(process);
        return res;
    }

#ifdef CONFIG_PROCFS
    res = procfs_register_process(process);
    if(res) {
        eprintk("Failed to register init process with procfs! (err=%s)\n",
                (sl_t)process->id,
                errnostr(res));
    }
#endif

    return 0;
}

declare_init_desc(launch, launch_init_process, "Launching init Process");

int
process_schedule(
        struct process *process) 
{
    int res;
    int irq_flags = spin_lock_irq_save(&process->status_lock);

    dprintk("scheduling process(%ld) thread(%ld)\n",
            process->id, process->thread.id);

    if(process->scheduler == NULL) {
        eprintk("process_schedule: process->scheduler == NULL!\n");
        spin_unlock_irq_restore(&process->status_lock, irq_flags);
        return -EINVAL;
    }

    switch(process->status) {
        case PROCESS_STATUS_SUSPEND:
            res = scheduler_add_thread(
                    process->scheduler,
                    &process->thread);
            if(res) {
                spin_unlock_irq_restore(&process->status_lock, irq_flags);
                return res;
            }
            process->status = PROCESS_STATUS_SCHEDULED;
            break;
        case PROCESS_STATUS_SCHEDULED:
            break;
        case PROCESS_STATUS_ZOMBIE:
            eprintk("process_schedule: Called on zombie thread!\n");
            spin_unlock_irq_restore(&process->status_lock, irq_flags);
            return -EINVAL;
        default:
            spin_unlock_irq_restore(&process->status_lock, irq_flags);
            panic("process_schedule: process has invalid status %ld\n",
                    (sl_t)process->status);
    }

    spin_unlock_irq_restore(&process->status_lock, irq_flags);

    return 0;
}

// The caller must be holding process->status_lock
static int
__process_suspend_caller_lock(
        struct process *process) 
{
    int res;

    switch(process->status) {
        case PROCESS_STATUS_SCHEDULED:
            if(process->scheduler != NULL) {
                res = scheduler_remove_thread(
                        process->scheduler,
                        &process->thread);
                if(res) {
                    return res;
                }
            }
            process->status = PROCESS_STATUS_SUSPEND;
            break;
        case PROCESS_STATUS_SUSPEND:
            break;
        case PROCESS_STATUS_ZOMBIE:
            eprintk("process_schedule: Called on zombie thread!\n");
            return -EINVAL;
        default:
            panic("process_schedule: process has invalid status %ld\n",
                    (sl_t)process->status);
    }

    return 0;
}

int
process_suspend(
        struct process *process)
{
    int res;
    int irq_flags = spin_lock_irq_save(&process->status_lock);
    res = __process_suspend_caller_lock(process);
    spin_unlock_irq_restore(&process->status_lock, irq_flags);
    return res;
}

int
process_set_scheduler(
        struct process *process,
        struct scheduler *sched)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(sched));

    int irq_flags = spin_lock_irq_save(&process->status_lock);

    if(process->status == PROCESS_STATUS_ZOMBIE) {
        wprintk("process_set_scheduler called on zombie process!\n");
    }

    if(process->status == PROCESS_STATUS_SCHEDULED
      && process->scheduler != NULL) {
        res = scheduler_remove_thread(process->scheduler, &process->thread);
        if(res) {
            eprintk("process_set_scheduler: Failed to remove process from old scheduler! (err=%s)\n",
                    errnostr(res));
            spin_unlock_irq_restore(&process->status_lock, irq_flags);
            return res;
        }
    }

    process->scheduler = sched;

    if(process->status == PROCESS_STATUS_SCHEDULED) {
        res = scheduler_add_thread(process->scheduler, &process->thread);
        if(res) {
            wprintk("process_set_scheduler: swapped schedulers but could not re-scheduler thread on new scheduler! (err=%s)\n",
                    errnostr(res));
            process->status = PROCESS_STATUS_SUSPEND;
        }
    }

    spin_unlock_irq_restore(&process->status_lock, irq_flags);
    return 0;
}

int
process_set_root_directory(
        struct process *process,
        struct fs_path *path)
{
    int res;

    res = fs_path_get(path);
    if(res) {
        eprintk("process_set_root_directory(%ld): fs_path_get failed: (err=%s)\n",
                process->id, errnostr(res));
        return res;
    }

    if(process->root_directory != NULL) {
        res = fs_path_put(process->root_directory);
        if(res) {
            eprintk("process_set_root(pid=%ld): fs_path_put failed: (err=%s)\n",
                    process->id, errnostr(res));
            fs_path_put(path);
            return res;
        }
    }

    process->root_directory = path;

    return 0;
}

int
process_set_working_directory(
        struct process *process,
        struct fs_path *path)
{
    int res;

    res = fs_path_get(path);
    if(res) {
        eprintk("process_set_working_directory(%ld): fs_path_get failed: (err=%s)\n",
                process->id, errnostr(res));
        return res;
    }

    if(process->working_directory != NULL) {
        res = fs_path_put(process->working_directory);
        if(res) {
            eprintk("process_set_working_directory(pid=%ld): fs_path_put failed: (err=%s)\n",
                    process->id, errnostr(res));
            fs_path_put(path);
            return res;
        }
    }

    process->working_directory = path;

    return 0;
}

int
process_write_usermem(
        struct process *process,
        void __user *dst,
        void * src,
        size_t length)
{
    int res;
    res = mmap_write(
            process,
            (uintptr_t)dst - (uintptr_t)process->mmap_ref->virt_addr,
            src,
            length);
    if(res) {
        return res;
    }
    return 0;
}

int
process_memset_usermem(
        struct process *process,
        void __user *dst,
        uint8_t val,
        size_t length)
{
    int res;
    res = mmap_memset(
            process,
            (uintptr_t)dst - (uintptr_t)process->mmap_ref->virt_addr,
            val,
            length);
    if(res) {
        return res;
    }
    return 0;
}

int
process_read_usermem(
        struct process *process,
        void *dst,
        void __user * src,
        size_t length)
{
    int res;
    res = mmap_read(
            process,
            (uintptr_t)src - (uintptr_t)process->mmap_ref->virt_addr,
            dst,
            length);
    if(res) {
        return res;
    }
    return 0;
}

int
process_strlen_usermem(
        struct process *process,
        const char __user *str,
        size_t max_len,
        size_t *out)
{
    int res;
    res = mmap_user_strlen(
            process,
            (uintptr_t)str - (uintptr_t)process->mmap_ref->virt_addr,
            max_len,
            out);
    if(res) {
        return res;
    }
    return 0;
}

int
process_get_reapable_child(
        struct process *parent,
        int nowait,
        pid_t *out_child_id)
{
    int res;
    int irq_flags = spin_lock_irq_save(&parent->hierarchy_lock);

    while(1) {
        size_t child_count = 0;
        ilist_node_t *list_node;
        ilist_for_each(list_node, &parent->children) {
            child_count++;
            struct process *child =
                container_of(list_node, struct process, child_node);
            if(child->status == PROCESS_STATUS_ZOMBIE) {
                spin_unlock_irq_restore(&parent->hierarchy_lock, irq_flags);
                *out_child_id = child->id;
                return 0;
            }
        }
        if(child_count == 0) {
            // Cannot without any children
            return -EINVAL;
        }

        if(nowait) {
            spin_unlock_irq_restore(&parent->hierarchy_lock, irq_flags);
            return -EWOULDBLOCK;
        } else {
            spin_unlock_irq_restore(&parent->hierarchy_lock, irq_flags);
            dprintk("PID(%ld) Sleeping on own child wait queue!\n", process->id);
            wait_on(&parent->child_wait_queue);
            irq_flags = spin_lock_irq_save(&parent->hierarchy_lock);
        }
    }
}

// Remove a process from the process hierarchy with 
// process->parent->hierarchy_lock and the global process_pid_lock held
static int
__process_reap_parent_lock(
        struct process *process)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->parent));

    

    // Remove the process from the hierarchy
    ilist_remove(&process->parent->children, &process->child_node);
    process->parent = NULL;

    // Free up the PID
    res = __process_remove_pid_lockless(process);
    if(res) {
        panic("__process_reap: process_remove_pid returned (%s)!\n",
                errnostr(res));
    }

    // Free the last bits of memory used by the process
    res = process_free(process);
    if(res) {
        panic("__process_reap: process_free returned (%s)!\n",
                errnostr(res));

    }

    return 0;
}

int
process_terminate(
        struct process *process,
        int exitcode) 
{
    DEBUG_ASSERT(process != NULL);

    int res;

    dprintk("process_terminate(%ld)\n", process->id);

    if(process == init_process) {
        panic("Trying to terminate the init process with exitcode=%d!\n",
                exitcode);
    }

    int irq_flags;

    irq_flags = spin_lock_irq_save(&process->status_lock);

    if(process->status == PROCESS_STATUS_ZOMBIE) {
        // process_terminate is idempotent
        wprintk("process_terminate is changing ZOMBIE error code from %d to %d!\n",
                process->exitcode, exitcode);
        process->exitcode = exitcode;
        spin_unlock_irq_restore(&process->status_lock, irq_flags);
        return 0;
    }

    DEBUG_ASSERT(process->parent != NULL);

    // Suspend the process (deregistering it with any schedulers)
    res = __process_suspend_caller_lock(process);
    if(res) {
        spin_unlock_irq_restore(&process->status_lock, irq_flags);
        eprintk("process_terminate: __process_suspend_caller_lock returned: %s\n",
                errnostr(res));
        process->refs = 1;
        return res;
    }

    DEBUG_ASSERT(process->status == PROCESS_STATUS_SUSPEND);

    /*
     * The process might actually still be running on some processor though
     * (the current thread is probably the process thread anyways)
     */

    process->exitcode = exitcode;
    process->status = PROCESS_STATUS_ZOMBIE;

#ifdef CONFIG_PROCFS
    res = procfs_deregister_process(process);
    if(res) {
        eprintk("Failed to deregister process from procfs on termination! (err=%s)\n",
                errnostr(res));
        process->refs = 1;
    }
#endif

    if(process->root_directory) {
        fs_path_put(process->root_directory);
    }
    if(process->working_directory) {
        fs_path_put(process->working_directory);
    }
    if(process->mmap) {
        mmap_deattach(process->mmap, process);
    }
    if(process->file_table) {
        file_table_deattach(process->file_table, process);
    }
    if(process->environ) {
        environment_deattach(process->environ, process);
    }

    // Terminate and Reap all children of this thread
    // NOTE: We acquire status_lock before hierarchy_lock here
    spin_lock(&process->hierarchy_lock);
    ilist_node_t *child_node;
    while(!ilist_empty(&process->children))
    {
        child_node = process->children.next;

        struct process *child =
            container_of(child_node, struct process, child_node);
        DEBUG_ASSERT(KERNEL_ADDR(child));
        DEBUG_ASSERT(child->parent == process);

        int child_exitcode;
        res = process_terminate(child, -EINTR);
        if(res) {
            eprintk("Failed to terminate child process during process_terminate! (err=%s)\n",
                    errnostr(res));
        }
        // This will remove the process from our list of children and deallocate the PID
        int irq_flags = spin_lock_irq_save(&process_pid_lock);
        res = __process_reap_parent_lock(child);
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        if(res) {
            eprintk("Failed to reap child process_during process_terminate! (err=%s)\n",
                    errnostr(res));
        }
    }

    if(process->parent) {
        // We need to wake anyone waiting on our parent's children
        // (This is usually just our parent doing a REAP_ANY)
        dprintk("Waking parent PID(%ld)'s child queue!\n", process->parent->id);
        wake_all(&process->parent->child_wait_queue);
    }

    // Wake up anyone waiting on us to terminate
    waitqueue_disable(&process->wait_queue);
    wake_all(&process->wait_queue);
    waitqueue_deinit(&process->wait_queue);

    // Wake up anyone waiting on our children to terminate
    waitqueue_disable(&process->child_wait_queue);
    wake_all(&process->child_wait_queue);
    waitqueue_deinit(&process->child_wait_queue);

    // We don't release the hierarchy lock,
    // because no one should ever be able to add/remove children
    // after this

    if(current_process() == process) {
        // IRQ's are left disabled because if we are running on the process' thread
        // (as is the case in an "exit" syscall) then once we suspend the process,
        // if we are preempted, then we will never be scheduled again to return.
        spin_unlock(&process->status_lock);
    } else {
        // This is some other process that we are forcing to terminate
        spin_unlock_irq_restore(&process->status_lock, irq_flags);
    } 
   
    return 0;
}

int
process_reap_child(
        struct process *parent,
        pid_t child_id,
        int *exitcode,
        int nowait)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(parent));

    int irq_flags = spin_lock_irq_save(&process_pid_lock);

    struct process *process = __process_from_pid_lockless(child_id);
    if(process == NULL) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
    }

    spin_lock(&parent->hierarchy_lock);

    while(process->status != PROCESS_STATUS_ZOMBIE) {
        if(nowait) {
            spin_unlock(&parent->hierarchy_lock);
            spin_unlock_irq_restore(&process_pid_lock, irq_flags);
            return -EWOULDBLOCK;
        } else {
            spin_unlock(&process->parent->hierarchy_lock);
            spin_unlock_irq_restore(&process_pid_lock, irq_flags);
            wait_on(&process->wait_queue);
            irq_flags = spin_lock_irq_save(&process_pid_lock);
            spin_lock(&process->parent->hierarchy_lock);
        }
    }

    if(exitcode) {
        *exitcode = process->exitcode;
    }

    res = __process_reap_parent_lock(process);
    if(res) {
        spin_unlock(&parent->hierarchy_lock);
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        wprintk("Leaving process in invalid state after attempted reap failed!\n");
        return res;
    }

    spin_unlock(&parent->hierarchy_lock);
    spin_unlock_irq_restore(&process_pid_lock, irq_flags);

    return 0;

err:
    spin_unlock_irq_restore(&process->parent->hierarchy_lock, irq_flags);
    return res;
}

struct process *
process_spawn_child(
        struct process *parent,
        void __user *user_entry,
        void *arg,
        unsigned long spawn_flags)
{
    int res;
    int exitcode;
    
    DEBUG_ASSERT(KERNEL_ADDR(parent));

    struct spawned_process_state *state =
        kmalloc(sizeof(struct spawned_process_state));
    if(state == NULL) {
        return NULL;
    }
    memset(state, 0, sizeof(struct spawned_process_state));

    state->arg = arg;
    state->entry = user_entry;

    struct process *process =
        process_alloc(
                spawned_process_kernel_entry,
                (void*)state,
                0,
                parent);
    if(process == NULL) {
        kfree(state);
        return NULL;
    }

    DEBUG_ASSERT(process->status == PROCESS_STATUS_SUSPEND);

    DEBUG_ASSERT(KERNEL_ADDR(parent->root_directory));

    res = process_set_root_directory(process, parent->root_directory);
    if(res) {
        eprintk("process_spawn_child: failed to set root directory! (err=%s)\n",
                errnostr(res));
        goto err1;
    }

    res = process_set_working_directory(process, parent->working_directory);
    if(res) {
        eprintk("process_spawn_child: failed to set working directory! (err=%s)\n",
                errnostr(res));
        goto err1;
    }

    if(spawn_flags & SPAWN_MMAP_CLONE) {
//        panic("SPAWN_MMAP_CLONE is unimplemented!\n");
        res = mmap_clone(parent->mmap, process);
        if(res) {
            eprintk("Failed to clone mmap for spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    } else {
        // SPAWN_MMAP_SHARED
        res = mmap_attach(parent->mmap, process);
        if(res) {
            eprintk("Failed to attach mmap to spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }

    if(spawn_flags & SPAWN_FILES_NONE) {
        res = file_table_create(process);
        if(res) {
            eprintk("Failed to create file table for spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    } else if(spawn_flags & SPAWN_FILES_CLONE) {
        res = file_table_clone(parent->file_table, process);
        if(res) {
            eprintk("Failed to clone file table for spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    } else {
        res = file_table_attach(parent->file_table, process);
        if(res) {
            eprintk("Failed to attach file table to spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }

    if(spawn_flags & SPAWN_ENV_NONE) {
        res = environment_create(process);
        if(res) {
            eprintk("Failed to create environment for spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    } else if(spawn_flags & SPAWN_ENV_CLONE) {
        res = environment_clone(parent->environ, process);
        if(res) {
            eprintk("Failed to clone environment for spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    } else {
        res = environment_attach(parent->environ, process);
        if(res) {
            eprintk("Failed to attach environment to spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    if(parent->tracked_exec) {
        process->tracked_exec = kstrdup(parent->tracked_exec);
    } else {
        process->tracked_exec = NULL;
    }
#endif

    res = process_set_scheduler(process, parent->scheduler);
    if(res) {
        eprintk("Failed to set spawned process scheduler! (err=%s)\n",
                errnostr(res));
        goto err1;
    }

    res = process_schedule(process);
    if(res) {
        eprintk("Failed to schedule spawned process! (err=%s)\n",
                errnostr(res));
        goto err1;
    }

    dprintk("spawned process (%ld)\n",
            (sl_t)process->id);

    //if(spawn_flags & SPAWN_MMAP_CLONE) {dump_process(do_printk, parent);dump_process(do_printk, process);}

#ifdef CONFIG_PROCFS
    res = procfs_register_process(process);
    if(res) {
        eprintk("Failed to register process(%ld) with procfs! (err=%s)\n",
                (sl_t)process->id,
                errnostr(res));
    }
#endif


    return process;

err1:
    process_terminate(process, 1);
    process_reap_child(parent, process->id, &exitcode, 0);
    DEBUG_ASSERT(exitcode == 1);
err0:
    return NULL;
}

int
process_send_signal(
        pid_t proc_id,
        signal_id_t id,
        unsigned long flags)
{
    int res;

    int irq_flags = spin_lock_irq_save(&process_pid_lock);

    struct ptree_node *node =
        ptree_get(&process_pid_tree, id);
    if(node == NULL) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        return -ENXIO;
    }

    struct process *proc =
        container_of(node, struct process, pid_node);

    DEBUG_ASSERT(KERNEL_ADDR(proc));

    res = signal_deliver(proc, id, flags);
    if(res) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        return res;
    }

    spin_unlock_irq_restore(&process_pid_lock, irq_flags);

    return 0;
}

