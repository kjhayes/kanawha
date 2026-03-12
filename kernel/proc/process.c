
#include <kanawha/assert.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/type.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/proc/process.h>
#include <kanawha/ramfile.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/thread.h>
#include <kanawha/timer.h>
#include <kanawha/types.h>
#include <kanawha/uapi/spawn.h>
#include <kanawha/usermode.h>
#include <kanawha/vmem.h>

static DECLARE_PTREE(process_pid_tree);
DEFINE_LOCAL_IRQ_LOCK(process_pid_lock);

static struct process *init_process = NULL;

void
dump_process(printk_f *printer, struct process *proc)
{
    (*printer)("\tPROCESS(%ld) (sched=%s) %s%s"
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
               "(exec=%s)"
#endif
               "%s\n",

               proc->id,

               proc->scheduler == NULL         ? "NONE"
               : proc->scheduler->name == NULL ? "UNNAMED"
                                               : proc->scheduler->name,

               proc->status == PROCESS_STATUS_SUSPEND     ? "[SUSPEND]"
               : proc->status == PROCESS_STATUS_SCHEDULED ? "[SCHEDULED]"
               : proc->status == PROCESS_STATUS_ZOMBIE
                   ? "[ZOMBIE]"
                   : "[INVALID-PROCESS-STATUS]",

               proc->thread.status == THREAD_STATUS_READY       ? "[READY]"
               : proc->thread.status == THREAD_STATUS_TIRED     ? "[TIRED]"
               : proc->thread.status == THREAD_STATUS_RUNNING   ? "[RUNNING]"
               : proc->thread.status == THREAD_STATUS_SLEEPING  ? "[SLEEPING]"
               : proc->thread.status == THREAD_STATUS_ABANDONED ? "[ABANDONED]"
               : proc->thread.status == THREAD_STATUS_PREPARING ? "[PREPARING]"
               : proc->thread.status == THREAD_STATUS_SCHEDULED
                   ? "[SCHEDULED]"
                   : "[INVALID-THREAD-STATUS]",

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
               proc->tracked_exec != NULL ? proc->tracked_exec : "NULL",
#endif
               "");
    //    mmap_dump(printer, proc->mmap);
}

void
dump_processes(printk_f *printer)
{
    process_pid_lock_acquire();
    struct ptree_node *node;
    node = ptree_get_first(&process_pid_tree);
    (*printer)("--- Process Table ---\n");
    while(node)
    {
        struct process *proc = container_of(node, struct process, pid_node);
        dump_process(printer, proc);
        node = ptree_get_next(node);
    }
    process_pid_lock_release();
}

static inline void
process_hierarchy_lock_acquire(struct process *process)
{
    dprintk("proc(%ld) acquiring proc(%ld)'s hierarchy lock\n",
            current_process()->id,
            process->id);
    irq_lock_acquire(&process->hierarchy_lock);
}
static inline void
process_hierarchy_lock_release(struct process *process)
{
    dprintk("proc(%ld) releasing proc(%ld)'s hierarchy lock\n",
            current_process()->id,
            process->id);
    irq_lock_release(&process->hierarchy_lock);
}

static inline struct process *
__process_from_pid_lockless(pid_t id)
{
    struct process *proc;

    struct ptree_node *node = ptree_get(&process_pid_tree, id);
    if(node == NULL)
    {
        return NULL;
    }

    proc = container_of(node, struct process, pid_node);
    return proc;
}

int
process_exists(pid_t id)
{
    process_pid_lock_acquire();
    struct ptree_node *node = ptree_get(&process_pid_tree, id);
    if(node == NULL)
    {
        process_pid_lock_release();
        return 0;
    }
    process_pid_lock_release();
    return 1;
}

int
process_id_to_user_id(pid_t id, uid_t *uid)
{
    process_pid_lock_acquire();

    struct ptree_node *node = ptree_get(&process_pid_tree, id);
    if(node == NULL)
    {
        process_pid_lock_release();
        return -ENXIO;
    }

    struct process *proc = container_of(node, struct process, pid_node);

    DEBUG_ASSERT(KERNEL_ADDR(proc));

    *uid = proc->user_id;

    process_pid_lock_release();

    return 0;
}

int
process_id_to_group_id(pid_t id, uid_t *gid)
{
    process_pid_lock_acquire();

    struct ptree_node *node = ptree_get(&process_pid_tree, id);
    if(node == NULL)
    {
        process_pid_lock_release();
        return -ENXIO;
    }

    struct process *proc = container_of(node, struct process, pid_node);

    DEBUG_ASSERT(KERNEL_ADDR(proc));

    *gid = proc->group_id;

    process_pid_lock_release();

    return 0;
}

int
process_get_parent_id(struct process *proc, pid_t *pid_out)
{
    int res;

    pid_t parent_id = proc->id;

    process_hierarchy_lock_acquire(proc);

    if(proc->parent != NULL)
    {
        parent_id = proc->parent->id;
    }

    process_hierarchy_lock_release(proc);

    *pid_out = parent_id;

    return 0;
}

static int
process_assign_pid(struct process *process)
{
    process_pid_lock_acquire();

    int res;
    res = ptree_insert_any(&process_pid_tree, &process->pid_node);
    if(res)
    {
        process_pid_lock_release();
        return res;
    }

    process->id = process->pid_node.key;

    process_pid_lock_release();
    return 0;
}

static int
__process_remove_pid_lockless(struct process *process)
{
    struct ptree_node *removed;
    removed = ptree_remove(&process_pid_tree, process->id);

    DEBUG_ASSERT(removed == &process->pid_node);
    return 0;
}
static int
__process_remove_pid(struct process *process)
{
    int res;
    process_pid_lock_acquire();
    res = __process_remove_pid_lockless(process);
    process_pid_lock_release();
    return res;
}

struct process *
current_process(void)
{
    struct thread_state *thread = current_thread();
    if(thread == NULL)
    {
        // We haven't even started threading yet
        return NULL;
    }

    if(thread->flags & THREAD_FLAG_PROCESS)
    {
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

    arch_on_process_entry();

    const char *binary_path = CONFIG_INIT_PROCESS_PATH;

    res =
        environment_set(process->environ,
                        "ARGV",
                        CONFIG_INIT_PROCESS_PATH " " CONFIG_INIT_PROCESS_ARGS);
    if(res)
    {
        panic("Failed to set init process ARGV! (err=%s)\n", errnostr(res));
    }

    fd_t binary_fd;
    struct fs_path *dir_path = process->root_directory;
    fs_path_get(dir_path);
    res = file_table_open(process->file_table,
                          process,
                          dir_path,
                          binary_path,
                          FILE_PERM_READ | FILE_PERM_EXEC,
                          0,
                          &binary_fd);
    fs_path_put(dir_path);
    if(res)
    {
        panic("Failed to find init process binary with path \"%s\" "
              "(err=%s)\n",
              binary_path,
              errnostr(res));
    }

    enable_irqs();

    res = syscall_exec(binary_fd, 0);
    if(res)
    {
        panic("Failed to exec the init process file \"%s\"! (err=%s)\n",
              binary_path,
              errnostr(res));
    }

    disable_irqs();

    dprintk("init_process_kernel_entry(%p)\n", NULL);

    enter_usermode(NULL);

    panic("enter_usermode Returned!\n");
}

static void
spawned_process_kernel_entry(void *in)
{
    int res;

    struct process *process = current_process();
    DEBUG_ASSERT(process);

    arch_on_process_entry();

    dprintk("spawned_process_kernel_entry(%p,%p)\n", entry, arg);

    enter_usermode(in);
}

static struct process *
process_alloc(thread_f *kernel_entry,
              void *kernel_in,
              unsigned long flags,
              struct process *parent)
{
    int res;

    struct process *process = kzmalloc(sizeof(struct process), KM_KERNEL);
    if(process == NULL)
    {
        eprintk("process_alloc: Out of Memory!\n");
        goto err0;
    }

    irq_lock_init(&process->status_lock);
    irq_lock_init(&process->hierarchy_lock);
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
    if(res)
    {
        eprintk("process_alloc: Failed to initialize process signal state!\n");
        goto err0;
    }

    res = thread_init(&process->thread,
                      kernel_entry,
                      kernel_in,
                      THREAD_FLAG_PROCESS);

    if(res)
    {
        eprintk("process_alloc: thread_init returned (%s)\n", errnostr(res));
        goto err1;
    }

    process->parent = parent;
    if(parent != NULL)
    {
        process_hierarchy_lock_acquire(parent);
        ilist_push_tail(&parent->children, &process->child_node);
        process->user_id = parent->user_id;
        process->group_id = parent->group_id;
        process_hierarchy_lock_release(parent);
    }
    else
    {
        DEBUG_ASSERT(flags & PROCESS_FLAG_INIT);
        process->user_id = INIT_UID;
        process->group_id = INIT_GID;
    }

    res = process_assign_pid(process);
    if(res)
    {
        eprintk("process_alloc: process_assign_pid returned (%s)\n",
                errnostr(res));
        goto err2;
    }

    {
        char wq_namebuf[64];

        snprintk(wq_namebuf, 64, "proc-%lu", (ul_t)process->id);
        wq_namebuf[63] = '\0';
        waitqueue_name(&process->wait_queue, wq_namebuf);
        snprintk(wq_namebuf, 64, "proc-%lu-children", (ul_t)process->id);
        wq_namebuf[63] = '\0';
        waitqueue_name(&process->child_wait_queue, wq_namebuf);
    }

    process->flags = flags;
    process->status = PROCESS_STATUS_SUSPEND;

    dprintk("allocated process(%ld) thread(%ld)\n",
            process->id,
            process->thread.id);

    return process;

    // err3:
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
    DEBUG_ASSERT(process->status == PROCESS_STATUS_ZOMBIE);
    DEBUG_ASSERT(process->thread.status == THREAD_STATUS_ABANDONED);

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    if(process->tracked_exec)
    {
        kfree((void *)process->tracked_exec);
    }
#endif

    thread_deinit(&process->thread);
    kfree(process);

    return 0;
}

static int
init_process_open_sysfs_file(const char *sysfs_name,
                             const char *file_name,
                             struct fs_node **node_out)
{
    int res;
    struct fs_mount *sysfs_mount = sysfs_mount_find(sysfs_name);
    if(sysfs_mount == NULL)
    {
        eprintk("Cannot find sysfs \"%s\"!\n", sysfs_name);
        return -ENXIO;
    }

    size_t sysfs_root_index;
    res = fs_mount_root_index(sysfs_mount, &sysfs_root_index);
    if(res)
    {
        eprintk("Failed to get root index of initial filesystem backing "
                "sysfs!\n");
        return res;
    }

    struct fs_node *sysfs_root =
        fs_mount_get_node(sysfs_mount, sysfs_root_index);
    if(sysfs_root == NULL)
    {
        eprintk("Cannot get sysfs root node \"%s\"!\n", sysfs_name);
        return -EINVAL;
    }

    size_t sysfs_file_index;
    res = fs_node_lookup(sysfs_root, file_name, &sysfs_file_index, NULL, 0);
    fs_node_put(sysfs_root);
    if(res != FS_NODE_LOOKUP_HARD)
    {
        eprintk("Failed to lookup sysfs file \"%s\" [%s]!\n",
                file_name,
                res < 0 ? errnostr(res)
                : res == FS_NODE_LOOKUP_SYMBOLIC
                    ? "cannot use symbolic link"
                    : "invalid return code from fs_node_lookup");
        return res;
    }

    struct fs_node *backing_node =
        fs_mount_get_node(sysfs_mount, sysfs_file_index);
    if(backing_node == NULL)
    {
        eprintk("Failed to get sysfs file \"%s\"!\n", file_name);
        return -EINVAL;
    }

    *node_out = backing_node;
    return 0;
}

static int
launch_init_process(void)
{
    int res;

    DEBUG_ASSERT_MSG(irqs_enabled(),
                     "Running launch_init_process with interrupts disabled!");

    if(init_process != NULL)
    {
        panic("launch_init_process: init_process is not NULL!\n");
    }

    struct process *process = process_alloc(init_process_kernel_entry,
                                            NULL,
                                            PROCESS_FLAG_INIT, // Flags
                                            NULL               // Parent
    );
    if(process == NULL)
    {
        panic("Failed to alloc init process!\n");
    }

    const char *fs_name = CONFIG_INITIAL_FS_FILESYSTEM;

    struct fs_type *type = fs_type_find(fs_name);
    if(type == NULL)
    {
        eprintk("Cannot find root fs filesystem type \"%s\"\n", fs_name);
        return -ENXIO;
    }

    struct fs_node *backing_node;
    res = init_process_open_sysfs_file(CONFIG_INITIAL_FS_BACKEND_SYSFS_DIR,
                                       CONFIG_INITIAL_FS_BACKEND_FILE_NAME,
                                       &backing_node);
    if(res)
    {
        eprintk("Failed to open backing file from sysfs for init process!\n");
        return res;
    }

    struct fs_mount *root_fs_mnt;
    res = fs_type_mount_file(type, backing_node, &root_fs_mnt);

    fs_node_put(backing_node);

    if(res)
    {
        return res;
    }

    struct fs_path *root;
    res = fs_path_mount_root(root_fs_mnt, &root);
    if(res)
    {
        return res;
    }

    res = process_set_root_directory(process, root);
    if(res)
    {
        eprintk("Failed to set init process root directory! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = process_set_working_directory(process, root);
    if(res)
    {
        eprintk("Failed to set init process working directory! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = mmap_create(PROCESS_LOWMEM_SIZE, process);
    if(process->mmap == NULL)
    {
        return res;
    }

    res = file_table_create(process);
    if(res)
    {
        eprintk("Failed to create init process file_table!\n", errnostr(res));
        return res;
    }

    res = environment_create(process);
    if(res)
    {
        return res;
    }

    init_process = process;

    dprintk("Created init Process (pid=%ld)\n", (sl_t)process->id);

    struct scheduler *sched = current_sched();
    if(sched == NULL)
    {
        eprintk("Could not find a scheduler on CPU (%ld)!\n",
                (sl_t)current_cpu_id());
        mmap_deattach(process->mmap, process);
        kfree(process);
        return -EINVAL;
    }

    res = process_set_scheduler(process, sched);
    if(res)
    {
        eprintk("Failed to set init process scheduler! (err=%s)\n",
                errnostr(res));
        mmap_deattach(process->mmap, process);
        kfree(process);
        return res;
    }

    res = process_schedule(process);
    if(res)
    {
        eprintk("Failed to schedule init process! (err=%s)\n", errnostr(res));
        mmap_deattach(process->mmap, process);
        kfree(process);
        return res;
    }

#ifdef CONFIG_PROCFS
    res = procfs_register_process(process);
    if(res)
    {
        eprintk("Failed to register init process with procfs! (err=%s)\n",
                (sl_t)process->id,
                errnostr(res));
    }
#endif

    return 0;
}

declare_init_desc(launch, launch_init_process, "Launching init Process");

int
process_schedule(struct process *process)
{
    int res;
    irq_lock_acquire(&process->status_lock);

    dprintk("scheduling process(%ld) thread(%ld)\n",
            process->id,
            process->thread.id);

    if(process->scheduler == NULL)
    {
        eprintk("process_schedule: process->scheduler == NULL!\n");
        irq_lock_release(&process->status_lock);
        return -EINVAL;
    }

    switch(process->status)
    {
    case PROCESS_STATUS_SUSPEND:
        res = scheduler_add_thread(process->scheduler, &process->thread);
        if(res)
        {
            irq_lock_release(&process->status_lock);
            return res;
        }
        process->status = PROCESS_STATUS_SCHEDULED;
        break;
    case PROCESS_STATUS_SCHEDULED:
        break;
    case PROCESS_STATUS_ZOMBIE:
        eprintk("process_schedule: Called on zombie thread!\n");
        irq_lock_release(&process->status_lock);
        return -EINVAL;
    default:
        irq_lock_release(&process->status_lock);
        panic("process_schedule: process has invalid status %ld\n",
              (sl_t)process->status);
    }

    irq_lock_release(&process->status_lock);

    return 0;
}

// The caller must be holding process->status_lock
static int
__process_suspend_caller_lock(struct process *process)
{
    int res;

    switch(process->status)
    {
    case PROCESS_STATUS_SCHEDULED:
        if(process->scheduler != NULL)
        {
            res = scheduler_remove_thread(process->scheduler, &process->thread);
            if(res)
            {
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
process_suspend(struct process *process)
{
    int res;
    irq_lock_acquire(&process->status_lock);
    res = __process_suspend_caller_lock(process);
    irq_lock_release(&process->status_lock);
    return res;
}

int
process_set_scheduler(struct process *process, struct scheduler *sched)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(sched));

    irq_lock_acquire(&process->status_lock);

    if(process->status == PROCESS_STATUS_ZOMBIE)
    {
        wprintk("process_set_scheduler called on zombie process!\n");
    }

    if(process->status == PROCESS_STATUS_SCHEDULED &&
       process->scheduler != NULL)
    {
        res = scheduler_remove_thread(process->scheduler, &process->thread);
        if(res)
        {
            eprintk("process_set_scheduler: Failed to remove process "
                    "from old "
                    "scheduler! (err=%s)\n",
                    errnostr(res));
            irq_lock_release(&process->status_lock);
            return res;
        }
    }

    process->scheduler = sched;

    if(process->status == PROCESS_STATUS_SCHEDULED)
    {
        res = scheduler_add_thread(process->scheduler, &process->thread);
        if(res)
        {
            wprintk("process_set_scheduler: swapped schedulers but "
                    "could not "
                    "re-schedule thread on new scheduler! (err=%s)\n",
                    errnostr(res));
            process->status = PROCESS_STATUS_SUSPEND;
        }
    }

    irq_lock_release(&process->status_lock);
    return 0;
}

int
process_set_root_directory(struct process *process, struct fs_path *path)
{
    int res;

    res = fs_path_get(path);
    if(res)
    {
        eprintk("process_set_root_directory(%ld): fs_path_get failed: "
                "(err=%s)\n",
                process->id,
                errnostr(res));
        return res;
    }

    if(process->root_directory != NULL)
    {
        res = fs_path_put(process->root_directory);
        if(res)
        {
            eprintk("process_set_root(pid=%ld): fs_path_put failed: "
                    "(err=%s)\n",
                    process->id,
                    errnostr(res));
            fs_path_put(path);
            return res;
        }
    }

    process->root_directory = path;

    return 0;
}

int
process_set_working_directory(struct process *process, struct fs_path *path)
{
    int res;

    res = fs_path_get(path);
    if(res)
    {
        eprintk("process_set_working_directory(%ld): fs_path_get failed: "
                "(err=%s)\n",
                process->id,
                errnostr(res));
        return res;
    }

    if(process->working_directory != NULL)
    {
        res = fs_path_put(process->working_directory);
        if(res)
        {
            eprintk("process_set_working_directory(pid=%ld): fs_path_put "
                    "failed: (err=%s)\n",
                    process->id,
                    errnostr(res));
            fs_path_put(path);
            return res;
        }
    }

    process->working_directory = path;

    return 0;
}

int
process_write_usermem(struct process *process,
                      void __user *dst,
                      void *src,
                      size_t length)
{
    int res;
    res = mmap_write(process,
                     (uintptr_t)dst - (uintptr_t)process->mmap_ref->virt_addr,
                     src,
                     length);
    if(res)
    {
        return res;
    }
    return 0;
}

int
process_memset_usermem(struct process *process,
                       void __user *dst,
                       uint8_t val,
                       size_t length)
{
    int res;
    res = mmap_memset(process,
                      (uintptr_t)dst - (uintptr_t)process->mmap_ref->virt_addr,
                      val,
                      length);
    if(res)
    {
        return res;
    }
    return 0;
}

int
process_read_usermem(struct process *process,
                     void *dst,
                     const void __user *src,
                     size_t length)
{
    int res;
    res = mmap_read(process,
                    (uintptr_t)src - (uintptr_t)process->mmap_ref->virt_addr,
                    dst,
                    length);
    if(res)
    {
        return res;
    }
    return 0;
}

int
process_strlen_usermem(struct process *process,
                       const char __user *str,
                       size_t max_len,
                       size_t *out)
{
    int res;
    res = mmap_user_strlen(process,
                           (uintptr_t)str -
                               (uintptr_t)process->mmap_ref->virt_addr,
                           max_len,
                           out);
    if(res)
    {
        return res;
    }
    return 0;
}

int
process_get_reapable_child(struct process *parent,
                           int nowait,
                           pid_t *out_child_id)
{
    int res;
    process_hierarchy_lock_acquire(parent);

    while(1)
    {
        size_t child_count = 0;
        ilist_node_t *list_node;
        ilist_for_each(list_node, &parent->children)
        {
            child_count++;
            struct process *child =
                container_of(list_node, struct process, child_node);
            if(child->status == PROCESS_STATUS_ZOMBIE)
            {
                process_hierarchy_lock_release(parent);
                *out_child_id = child->id;
                return 0;
            }
        }
        if(child_count == 0)
        {
            process_hierarchy_lock_release(parent);
            if(nowait)
            {
                return -EWOULDBLOCK;
            }
            // Cannot wait without any children
            return -EINVAL;
        }

        if(nowait)
        {
            process_hierarchy_lock_release(parent);
            return -EWOULDBLOCK;
        }
        else
        {
            process_hierarchy_lock_release(parent);
            dprintk("PID(%ld) Sleeping on own child wait queue!\n",
                    process->id);
            res = wait_on(&parent->child_wait_queue);
            if(res)
            {
                return res;
            }
            process_hierarchy_lock_acquire(parent);
        }
    }
}

// Remove a process from the process hierarchy with
// process->parent->hierarchy_lock and the global process_pid_lock held
static int
__process_reap_parent_lock(struct process *process)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->parent));
    DEBUG_ASSERT(process->status == PROCESS_STATUS_ZOMBIE);
    DEBUG_ASSERT(process->thread.status == THREAD_STATUS_ABANDONED);

    // Remove the process from the hierarchy
    ilist_remove(&process->parent->children, &process->child_node);
    process->parent = NULL;

    // Free up the PID
    res = __process_remove_pid_lockless(process);
    if(res)
    {
        panic("__process_reap: process_remove_pid returned (%s)!\n",
              errnostr(res));
    }

    // Free the last bits of memory used by the process
    res = process_free(process);
    if(res)
    {
        panic("__process_reap: process_free returned (%s)!\n", errnostr(res));
    }

    return 0;
}

int
process_terminate(int exitcode)
{
#ifdef CONFIG_DEBUG_PROCESS_TERMINATION
#define LOG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

    struct process *process = current_process();
    if(process == NULL)
    {
        return -EINVAL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(process));

    int res;

    LOG("process_terminate(pid=%ld, exitcode=%d (%s))\n",
        process->id,
        exitcode,
        errnostr(exitcode));

    if(process == init_process)
    {
        wprintk("Trying to terminate the init process "
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
                "\"%s\" "
#endif
                "with exitcode=%d!\n",
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
                process->tracked_exec ? process->tracked_exec : "UNKNOWN",
#endif
                exitcode);
        return -EINVAL;
    }

    process_hierarchy_lock_acquire(process);

    // Fatally signal all children of this process
    ilist_node_t *child_node;
    ilist_for_each(child_node, &process->children)
    {
        struct process *child =
            container_of(child_node, struct process, child_node);
        DEBUG_ASSERT(KERNEL_ADDR(child));
        DEBUG_ASSERT(child->parent == process);

        printk("PID(%d) fatally signalling child (%d)\n",
               (s_t)process->id,
               (s_t)child->id);
        res = signal_deliver(child,
                             SIGNAL_ID_ORPHANED,
                             SIGNAL_FLAG_FATAL | SIGNAL_FLAG_COALESCE);
        if(res)
        {
            process_hierarchy_lock_release(process);
            eprintk("process_terminate failed to signal all children!\n");
            return res;
        }
    }

    // Keep reaping children until we have none
    while(!ilist_empty(&process->children))
    {
        printk("Still waiting on children:\n");
        ilist_for_each(child_node, &process->children)
        {
            struct process *child =
                container_of(child_node, struct process, child_node);
            dump_process(do_printk, child);
        }
        dump_threads(do_printk);
        process_hierarchy_lock_release(process);
        pid_t to_reap_id;
        res = process_get_reapable_child(process, 0, &to_reap_id);
        if(res == 0)
        {
            int exitcode;
            res = process_reap_child(process, to_reap_id, &exitcode, 0);
            if(res)
            {
                wprintk("Failed to reap child of process during "
                        "termination!\n");
            }
        }
        else
        {
            wprintk("Failed to get child of process to reap during "
                    "termination!\n");
        }
        printk("PID(%d) reaped child! (%lu remaining)\n",
               (s_t)process->id,
               (ul_t)ilist_count(&process->children));
        process_hierarchy_lock_acquire(process);
    }
    process_hierarchy_lock_release(process);

    printk("PID(%d) reaped all children!\n", process->id);

    irq_lock_acquire(&process->status_lock);

    DEBUG_ASSERT(KERNEL_ADDR(process->parent) || process->parent == NULL);

    if(process->status == PROCESS_STATUS_ZOMBIE)
    {
        // process_terminate is idempotent
        wprintk("process_terminate is changing ZOMBIE error code from %d "
                "to %d!\n",
                process->exitcode,
                exitcode);
        process->exitcode = exitcode;
        irq_lock_release(&process->status_lock);
        return 0;
    }

    DEBUG_ASSERT(process->parent != NULL);

    // Suspend the process (deregistering it with any schedulers)
    res = __process_suspend_caller_lock(process);
    if(res)
    {
        irq_lock_release(&process->status_lock);
        eprintk("process_terminate: __process_suspend_caller_lock "
                "returned: %s\n",
                errnostr(res));
        return res;
    }

    DEBUG_ASSERT(process->status == PROCESS_STATUS_SUSPEND);

    process->exitcode = exitcode;
    process->status = PROCESS_STATUS_ZOMBIE;

#ifdef CONFIG_PROCFS
    res = procfs_deregister_process(process);
    if(res)
    {
        eprintk("Failed to deregister process from procfs on termination! "
                "(err=%s)\n",
                errnostr(res));
    }
#endif

    if(process->root_directory)
    {
        fs_path_put(process->root_directory);
    }
    if(process->working_directory)
    {
        fs_path_put(process->working_directory);
    }
    if(process->mmap)
    {
        mmap_deattach(process->mmap, process);
    }
    if(process->file_table)
    {
        file_table_deattach(process->file_table, process);
    }
    if(process->environ)
    {
        environment_deattach(process->environ, process);
    }

    if(process->parent)
    {
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

    // IRQ's are left disabled because if we are running on the process' thread
    // (as is the case in an "exit" syscall) then once we suspend the process,
    // if we are preempted, then we will never be scheduled again to return.
    irq_lock_release_no_enable_irqs(&process->status_lock);

    printk("PID(%ld) finished process terminate!\n", process->id);
    return 0;

#undef LOG
}

int
process_reap_child(struct process *parent,
                   pid_t child_id,
                   int *exitcode,
                   int nowait)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(parent));

    process_pid_lock_acquire();

    struct process *process = __process_from_pid_lockless(child_id);
    if(process == NULL)
    {
        process_pid_lock_release();
        return -ENXIO;
    }

    if(process->parent != parent)
    {
        process_pid_lock_release();
        return -ENXIO;
    }

    process_hierarchy_lock_acquire(parent);

    while(process->status != PROCESS_STATUS_ZOMBIE
       || process->thread.status != THREAD_STATUS_ABANDONED)
    {
        if(nowait)
        {
            process_hierarchy_lock_release(parent);
            process_pid_lock_release();
            return -EWOULDBLOCK;
        }
        else
        {
            process_hierarchy_lock_release(parent);
            process_pid_lock_release();
            res = wait_on(&process->wait_queue);
            if(res)
            {
                return res;
            }
            process_pid_lock_acquire();
            process_hierarchy_lock_acquire(parent);
        }
    }

    if(exitcode)
    {
        *exitcode = process->exitcode;
    }

    res = __process_reap_parent_lock(process);
    if(res)
    {
        process_hierarchy_lock_release(parent);
        process_pid_lock_release();
        wprintk("Leaving process in invalid state after attempted reap "
                "failed!\n");
        return res;
    }

    process_hierarchy_lock_release(parent);
    process_pid_lock_release();

    return 0;
}

struct process *
process_spawn_child(struct process *parent,
                    void __user *user_entry,
                    void *arg,
                    unsigned long spawn_flags)
{
    int res;
    int exitcode;

    DEBUG_ASSERT(KERNEL_ADDR(parent));

    struct process *process =
        process_alloc(spawned_process_kernel_entry, (void *)arg, 0, parent);
    if(process == NULL)
    {
        return NULL;
    }

    process->user_ip = user_entry;

    DEBUG_ASSERT(process->status == PROCESS_STATUS_SUSPEND);

    DEBUG_ASSERT(KERNEL_ADDR(parent->root_directory));

    res = signal_state_init_on_spawn(&parent->signal_state,
                                     &process->signal_state);
    if(res)
    {
        eprintk("process_spawn_child: failed to setup child signal state! "
                "(err=%s)\n",
                errnostr(res));
        goto err1;
    }

    res = process_set_root_directory(process, parent->root_directory);
    if(res)
    {
        eprintk("process_spawn_child: failed to set root directory! "
                "(err=%s)\n",
                errnostr(res));
        goto err1;
    }

    res = process_set_working_directory(process, parent->working_directory);
    if(res)
    {
        eprintk("process_spawn_child: failed to set working directory! "
                "(err=%s)\n",
                errnostr(res));
        goto err1;
    }

    if(spawn_flags & SPAWN_MMAP_CLONE)
    {
        res = mmap_clone(parent->mmap, process);
        if(res)
        {
            eprintk("Failed to clone mmap for spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }
    else
    {
        // SPAWN_MMAP_SHARED
        res = mmap_attach(parent->mmap, process);
        if(res)
        {
            eprintk("Failed to attach mmap to spawned process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }

    if(spawn_flags & SPAWN_FILES_NONE)
    {
        res = file_table_create(process);
        if(res)
        {
            eprintk("Failed to create file table for spawned "
                    "process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }
    else if(spawn_flags & SPAWN_FILES_CLONE)
    {
        res = file_table_clone(parent->file_table, process);
        if(res)
        {
            eprintk("Failed to clone file table for spawned process! "
                    "(err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }
    else
    {
        res = file_table_attach(parent->file_table, process);
        if(res)
        {
            eprintk("Failed to attach file table to spawned process! "
                    "(err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }

    if(spawn_flags & SPAWN_ENV_NONE)
    {
        res = environment_create(process);
        if(res)
        {
            eprintk("Failed to create environment for spawned "
                    "process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }
    else if(spawn_flags & SPAWN_ENV_CLONE)
    {
        res = environment_clone(parent->environ, process);
        if(res)
        {
            eprintk("Failed to clone environment for spawned "
                    "process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }
    else
    {
        res = environment_attach(parent->environ, process);
        if(res)
        {
            eprintk("Failed to attach environment to spawned "
                    "process! (err=%s)\n",
                    errnostr(res));
            goto err1;
        }
    }

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    if(parent->tracked_exec)
    {
        process->tracked_exec = kstrdup(parent->tracked_exec);
    }
    else
    {
        process->tracked_exec = NULL;
    }
#endif

    res = process_set_scheduler(process, parent->scheduler);
    if(res)
    {
        eprintk("Failed to set spawned process scheduler! (err=%s)\n",
                errnostr(res));
        goto err1;
    }

    res = process_schedule(process);
    if(res)
    {
        eprintk("Failed to schedule spawned process! (err=%s)\n",
                errnostr(res));
        goto err1;
    }

    dprintk("spawned process (%ld)\n", (sl_t)process->id);

    // if(spawn_flags & SPAWN_MMAP_CLONE) {dump_process(do_printk,
    // parent);dump_process(do_printk, process);}

#ifdef CONFIG_PROCFS
    res = procfs_register_process(process);
    if(res)
    {
        eprintk("Failed to register process(%ld) with procfs! (err=%s)\n",
                (sl_t)process->id,
                errnostr(res));
    }
#endif

    return process;

err1:
    // process_terminate(process, 1);
    // TODO
    panic(
        "NEED TO HANDLE DEALLOCATING A KILLED PROCESS DURING PROCESS SPAWN\n");
    process_reap_child(parent, process->id, &exitcode, 0);
    DEBUG_ASSERT(exitcode == 1);
    // err0:
    return NULL;
}

int
process_send_signal(pid_t proc_id, signal_id_t id, unsigned long flags)
{
    int res;

    process_pid_lock_acquire();

    struct ptree_node *node = ptree_get(&process_pid_tree, proc_id);
    if(node == NULL)
    {
        process_pid_lock_release();
        return -ENXIO;
    }

    struct process *proc = container_of(node, struct process, pid_node);

    DEBUG_ASSERT(KERNEL_ADDR(proc));

    res = signal_deliver(proc, id, flags);
    if(res)
    {
        process_pid_lock_release();
        return res;
    }

    process_pid_lock_release();

    process_force_awake(id);

    return 0;
}

int
process_force_awake(pid_t proc_id)
{
    int res;
    process_pid_lock_acquire();

    struct ptree_node *node = ptree_get(&process_pid_tree, proc_id);
    if(node == NULL)
    {
        process_pid_lock_release();
        return -ENXIO;
    }

    struct process *proc = container_of(node, struct process, pid_node);

    DEBUG_ASSERT(KERNEL_ADDR(proc));

    res = thread_wake(&proc->thread);
    if(res)
    {
        process_pid_lock_release();
        return res;
    }

    process_pid_lock_release();

    return 0;
}

__attribute__((weak)) int
arch_on_process_entry(void)
{
    // By default do nothing and let the architecture
    // provide a strong symbol if necessary.
    return 0;
}
