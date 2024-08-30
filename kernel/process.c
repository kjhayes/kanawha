
#include <kanawha/process.h>
#include <kanawha/thread.h>
#include <kanawha/stdint.h>
#include <kanawha/vmem.h>
#include <kanawha/init.h>
#include <kanawha/usermode.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/timer.h>
#include <kanawha/assert.h>
#include <kanawha/syscall/mmap.h>

#define PROCESS_LOWMEM_SIZE (1ULL<<32)

static DECLARE_SPINLOCK(process_pid_lock);
static DECLARE_PTREE(process_pid_tree);

#define MAX_PROCESS_ID (process_id_t)(uintptr_t)(-1)

static struct process *init_process = NULL;

int
process_force_ip(
        struct process *process,
        void __user *ip)
{
    spin_lock(&process->signal_lock);
    if(process->forcing_ip) {
        spin_unlock(&process->signal_lock);
        return -EALREADY;
    }
    process->forcing_ip = 1;
    process->forced_ip = ip;
    spin_unlock(&process->signal_lock);
    return 0;
}

int
process_clear_forced_ip(
        struct process *process)
{
    spin_lock(&process->signal_lock);
    process->forcing_ip = 0;
    process->forced_ip = NULL;
    spin_unlock(&process->signal_lock);
    return 0;
}

static int
process_assign_pid(
        struct process *process)
{
    int irq_flags = spin_lock_irq_save(&process_pid_lock);

    process_id_t free_pid = MAX_PROCESS_ID;

    for(process_id_t pid = 0; pid < MAX_PROCESS_ID; pid++) {
        struct ptree_node *node = ptree_get(&process_pid_tree, pid);
        if(node == NULL) {
            free_pid = pid;
            break;
        }
    }

    if(free_pid == MAX_PROCESS_ID) {
        spin_unlock_irq_restore(&process_pid_lock, irq_flags);
        return -ENOMEM;
    }

    process->id = free_pid;
    process->pid_node.key = free_pid;
    ptree_insert(&process_pid_tree, &process->pid_node, free_pid);

    spin_unlock_irq_restore(&process_pid_lock, irq_flags);
    return 0;
}

static int
process_remove_pid(
        struct process *process)
{
    int irq_flags = spin_lock_irq_save(&process_pid_lock);

    process_id_t free_pid = MAX_PROCESS_ID;

    struct ptree_node *removed;
    removed = ptree_remove(&process_pid_tree, process->id);

    DEBUG_ASSERT(removed == &process->pid_node);

    spin_unlock_irq_restore(&process_pid_lock, irq_flags);
    return 0;

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

    fd_t binary_fd;
    res = file_table_open_path(
            &process->file_table,
            binary_path,
            FILE_PERM_READ|FILE_PERM_EXEC,
            0,
            &binary_fd); 
    if(res) {
        panic("Failed to find init process binary with path \"%s\" (err=%s)\n",
                binary_path, errnostr(res));
    }

    DEBUG_ASSERT(binary_fd != NULL_FD);

    res = syscall_exec(
            process,
            binary_fd,
            0);
    if(res) {
        panic("Failed to exec the init process file \"%s\"! (err=%s)\n",
                binary_path, errnostr(res));
    }

//    size_t node_size;
//    {
//      struct file_descriptor *desc =
//          file_table_get_descriptor(
//                  &process->file_table,
//                  binary_fd);
//      if(desc == NULL) {
//          panic("Failed to get init binary file descriptor!\n");
//      }
//
//      res = fs_node_attr(
//              desc->node,
//              FS_NODE_ATTR_MAX_OFFSET_END,
//              &node_size);
//      if(res) {
//          panic("Failed to get init process binary size! (err=%s)\n",
//                  errnostr(res));
//      }
//
//      res = file_table_put_descriptor(
//                  &process->file_table,
//                  desc);
//      if(res) {
//          panic("Failed to put init binary file descriptor! (err=%s)\n",
//                  errnostr(res));
//      }
//    }
//
//    // Align our request size up by a page
//    if(ptr_orderof(node_size) < VMEM_MIN_PAGE_ORDER) {
//        node_size &= ~((1ULL<<VMEM_MIN_PAGE_ORDER)-1);
//        node_size += 1ULL<<VMEM_MIN_PAGE_ORDER;
//    }
//
//    res = mmap_map_region(
//        current_process(),
//        binary_fd,
//        0x0,
//        CONFIG_INIT_PROCESS_BINARY_VIRT_ADDRESS,
//        node_size,
//        MMAP_PROT_READ|MMAP_PROT_EXEC,
//        MMAP_PRIVATE);
//
//    if(res) {
//        panic("Failed to mmap init process! (err=%s)\n",
//                errnostr(res));
//    }
//
//    res = file_table_close_file(
//            &process->file_table,
//            binary_fd);
//    if(res) {
//        wprintk("Failed to close init process binary file descriptor after mapping! (err=%s)\n",
//                errnostr(res));
//    }
//
//    dprintk("init_process_kernel_entry: (entering usermode at address %p)\n",
//            entry_point);
    enter_usermode(NULL);
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
        goto err0;
    }
    memset(process, 0, sizeof(struct process));

    res = mmap_init(process, PROCESS_LOWMEM_SIZE);
    if(res) {
        goto err1;
    }

    res = thread_init(
            &process->thread,
            kernel_entry,
            kernel_in,
            THREAD_FLAG_PROCESS);

    if(res) {
        goto err2;
    }

    res = process_assign_pid(process);
    if(res) {
        goto err3;
    }

    res = vmem_map_map_region(process->thread.mem_map, process->mmap.vmem_region, 0x0);
    if(res) {
        eprintk("Failed to map mmap into process vmem_map! (err=%s)\n",
                errnostr(res));
        goto err4;
    }

    process->mmap_ref = vmem_map_get_region(process->thread.mem_map, 0x0);
    if(process->mmap_ref == NULL) {
       eprintk("Failed to get process vmem_region_ref of process mmap!\n",
                errnostr(res));
        goto err4;
    }

    res = file_table_init(process, &process->file_table);
    if(res) {
        eprintk("Failed to initialize process file table! (err=%s)\n",
                errnostr(res));
        goto err4;
    }

    spinlock_init(&process->status_lock);
    spinlock_init(&process->hierarchy_lock);

    ilist_init(&process->children);
   
    process->parent = parent;
    if(parent != NULL) {
        spin_lock(&parent->hierarchy_lock);
        ilist_push_tail(&parent->children, &process->child_node);
        spin_unlock(&parent->hierarchy_lock);
    }

    process->flags = flags;
    process->status = PROCESS_STATUS_SUSPEND;

    return process;

err5:
    file_table_deinit(process, &process->file_table);
err4:
    process_remove_pid(process);
err3:
    thread_deinit(&process->thread);
err2:
    mmap_deinit(process);
err1:
    kfree(process);
err0:
    return NULL;
}

static int
process_free(struct process *process)
{
    file_table_deinit(process, &process->file_table);
    process_remove_pid(process);
    thread_deinit(&process->thread);
    mmap_deinit(process);
    kfree(process);
    return 0;
}

static int
launch_init_process(void)
{
    int res;

    if(init_process != NULL) {
        panic("launch_init_process: init_process is not NULL!\n");
    }

    struct process *process = process_alloc(
            init_process_kernel_entry,
            NULL,
            PROCESS_FLAG_INIT, // Flags
            NULL // Parent
            );

    init_process = process;

    printk("Created init Process (pid=%ld)\n",
            (sl_t)process->id);

    struct scheduler *sched = current_sched();
    if(sched == NULL) {
        eprintk("Could not find a scheduler on CPU (%ld)!\n",
                (sl_t)current_cpu_id());
        mmap_deinit(process);
        kfree(process);
        return -EINVAL;
    }

    res = process_set_scheduler(process, sched);
    if(res) {
        eprintk("Failed to set init process scheduler! (err=%s)\n",
                errnostr(res));
        mmap_deinit(process);
        kfree(process);
        return res;
    }

    res = process_schedule(process);
    if(res) {
        eprintk("Failed to schedule init process! (err=%s)\n",
                errnostr(res));
        mmap_deinit(process);
        kfree(process);
        return res;
    }

    return 0;
}

declare_init_desc(launch, launch_init_process, "Launching init Process");

int
process_schedule(
        struct process *process) 
{
    int res;
    int irq_flags = spin_lock_irq_save(&process->status_lock);

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

int
process_suspend(
        struct process *process) 
{
    int res;
    int irq_flags = spin_lock_irq_save(&process->status_lock);

    if(process->scheduler == NULL) {
        eprintk("process_suspend: process->scheduler == NULL!\n");
        spin_unlock_irq_restore(&process->status_lock, irq_flags);
        return -EINVAL;
    }

    switch(process->status) {
        case PROCESS_STATUS_SCHEDULED:
            res = scheduler_remove_thread(
                    process->scheduler,
                    &process->thread);
            if(res) {
                spin_unlock_irq_restore(&process->status_lock, irq_flags);
                return res;
            }
        case PROCESS_STATUS_SUSPEND:
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

int
process_set_scheduler(
        struct process *process,
        struct scheduler *sched)
{
    int res;

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
process_terminate(
        struct process *process,
        int exitcode) 
{
    DEBUG_ASSERT(process != NULL);

    if(process == init_process) {
        panic("Trying to terminate the init process with exitcode=%d!\n",
                exitcode);
    }

    DEBUG_ASSERT(process->parent != NULL);

    if(process->status == PROCESS_STATUS_ZOMBIE) {
        eprintk("process_terminate: Called on zombie process!\n");
        return -EINVAL;
    }

    int irq_flags = spin_lock_irq_save(&process->status_lock);

    process->exitcode = exitcode;
    process->status = PROCESS_STATUS_ZOMBIE;

    spin_unlock_irq_restore(&process->status_lock, irq_flags);
    
    return 0;
}



