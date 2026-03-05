
#include <kanawha/irq.h>
#include <kanawha/proc/process.h>
#include <kanawha/strace.h>
#include <kanawha/syscall.h>

#define __KANAWHA_SYSCALL_KEEP_XLIST
#include <kanawha/uapi/syscall.h>

static int
syscall_unknown(syscall_id_t id)
{
    struct process *process = current_process();
    eprintk("process(%ld) Unknown syscall (%ld)\n",
            (sl_t)process->id,
            (sl_t)id);
    return 0;
}

int
handle_syscall(syscall_id_t id, struct syscall_args *args, uint64_t *ret_out)
{
    uint64_t ret_val;

    struct process *process = current_process();
    DEBUG_ASSERT(KERNEL_ADDR(process));

    DEBUG_ASSERT_MSG(irqs_enabled(), "Handling syscall with IRQ(s) disabled!");

    strace_begin_syscall(process, id);
#ifdef CONFIG_STRACE_TIME_SYSCALLS
    time_t __start_time = current_timestamp();
#endif

    switch(id)
    {
    case SYSCALL_ID_EXIT:
        syscall_exit(args->args[0]);
        break;
    case SYSCALL_ID_OPEN:
        ret_val = (uint64_t)(fd_t)syscall_open(
            (const char __user *)args->args[0], // path
            (unsigned long)args->args[1],       // access_flags
            (unsigned long)args->args[2],       // mode_flags
            (fd_t __user *)args->args[3]        // fd_out
        );
        break;
    case SYSCALL_ID_CLOSE:
        ret_val = (int)syscall_close((fd_t)args->args[0]);
        break;
    case SYSCALL_ID_READ:
        ret_val =
            (uint64_t)(ssize_t)syscall_read((fd_t)args->args[0], // file
                                            (void __user *)args->args[1], // dst
                                            (size_t)args->args[2] // size
            );
        break;
    case SYSCALL_ID_WRITE:
        ret_val = (uint64_t)(ssize_t)syscall_write(
            (fd_t)args->args[0],          // file
            (void __user *)args->args[1], // src
            (size_t)args->args[2]         // size
        );
        break;
    case SYSCALL_ID_FLUSH:
        ret_val =
            (uint64_t)(int)syscall_flush((fd_t)args->args[0],         // file
                                         (unsigned long)args->args[1] // flags
            );
        break;
    case SYSCALL_ID_SEEK:
        ret_val =
            (uint64_t)(ssize_t)syscall_seek((fd_t)args->args[0],    // file
                                            (ssize_t)args->args[1], // offset
                                            (int)args->args[2]      // whence
            );
        break;
    case SYSCALL_ID_MMAP:
        ret_val = (uint64_t)(int)syscall_mmap(
            (fd_t)args->args[0],                  // file
            (size_t)args->args[1],                // file offset
            (void __user *__user *)args->args[2], // where
            (size_t)args->args[3],                // size
            (unsigned long)args->args[4]          // mmap_flags
        );
        break;
    case SYSCALL_ID_MUNMAP:
        ret_val = (uint64_t)(int)syscall_munmap(
            (void __user *)args->args[0] // mapping
        );
        break;
    case SYSCALL_ID_EXEC:
        ret_val = (uint64_t)(int)syscall_exec(
            (fd_t)args->args[0],         // file
            (unsigned long)args->args[1] // exec_flags
        );
        break;
    case SYSCALL_ID_GETCWD:
        ret_val = (uint64_t)(int)syscall_getcwd(
            (char __user *)args->args[0], // buffer
            (size_t)args->args[1]         // buflen
        );
        break;
    case SYSCALL_ID_ENVIRON:
        ret_val = (uint64_t)(int)syscall_environ(
            (const char __user *)args->args[0], // key
            (char __user *)args->args[1],       // value
            (size_t)args->args[2],              // len
            (int)args->args[3]                  // operation
        );
        break;
    case SYSCALL_ID_SPAWN:
        ret_val =
            (uint64_t)(int)syscall_spawn((void __user *)args->args[0], // entry
                                         (void *)args->args[1],        // arg
                                         (unsigned long)args->args[2], // flags
                                         (pid_t __user *)args->args[3] // child
            );
        break;
    case SYSCALL_ID_REAP:
        ret_val = (uint64_t)(int)syscall_reap(
            (unsigned long)args->args[0],  // flags
            (pid_t __user *)args->args[1], // pid_inout
            (int __user *)args->args[2]    // exitcode
        );
        break;
    case SYSCALL_ID_FACCESS:
        ret_val = (uint64_t)(int)syscall_faccess(
            (fd_t)args->args[0],          // file
            (unsigned long)args->args[1], // fields
            (unsigned long)args->args[2]  // mode
        );
        break;
    case SYSCALL_ID_MOUNT:
        ret_val = (uint64_t)(int)syscall_mount(
            (const char __user *)args->args[0], // source
            (fd_t)args->args[1],                // dst_dir
            (const char __user *)args->args[2], // dst_name
            (const char __user *)args->args[3], // fs_type
            (unsigned long)args->args[4]        // flags
        );
        break;
    case SYSCALL_ID_UNMOUNT:
        ret_val =
            (uint64_t)(int)syscall_unmount((fd_t)args->args[0] // mount point
            );
        break;
    case SYSCALL_ID_DIRBEGIN:
        ret_val = (uint64_t)(int)syscall_dirbegin((fd_t)args->args[0] // dir
        );
        break;
    case SYSCALL_ID_DIRNEXT:
        ret_val = (uint64_t)(int)syscall_dirnext((fd_t)args->args[0] // dir
        );
        break;
    case SYSCALL_ID_DIRATTR:
        ret_val = (uint64_t)(int)syscall_dirattr(
            (fd_t)args->args[0],           // mount point
            (int)args->args[1],            // attr
            (size_t __user *)args->args[2] // value
        );
        break;
    case SYSCALL_ID_DIRNAME:
        ret_val = (uint64_t)(int)syscall_dirname(
            (fd_t)args->args[0],          // mount point
            (char __user *)args->args[1], // buffer
            (size_t)args->args[2]         // buflen
        );
        break;
    case SYSCALL_ID_FMOVE:
        ret_val =
            (uint64_t)(int)syscall_fmove((fd_t)args->args[0],          // fd0
                                         (fd_t)args->args[1],          // fd1
                                         (unsigned long)args->args[2], // flags
                                         (fd_t __user *)args->args[3]  // out
            );
        break;
    case SYSCALL_ID_FATTR:
        ret_val = (uint64_t)(int)syscall_fattr((fd_t)args->args[0],
                                               (int)args->args[1],
                                               (size_t __user *)args->args[2]);
        break;
    case SYSCALL_ID_MKFILE:
        ret_val = (uint64_t)(int)syscall_mkfile(
            (fd_t)args->args[0],                // dir
            (const char __user *)args->args[1], // file_name
            (unsigned long)args->args[2]);
        break;
    case SYSCALL_ID_MKDIR:
        ret_val = (uint64_t)(int)syscall_mkdir(
            (fd_t)args->args[0],                // dir
            (const char __user *)args->args[1], // name
            (unsigned long)args->args[2]        // flags
        );
        break;
    case SYSCALL_ID_LINK:
        ret_val = (uint64_t)(int)syscall_link(
            (fd_t)args->args[0],                // from
            (fd_t)args->args[1],                // dir
            (const char __user *)args->args[2], // link_name
            (unsigned long)args->args[3]        // flags
        );
        break;
    case SYSCALL_ID_SYMLINK:
        ret_val = (uint64_t)(int)syscall_symlink(
            (const char __user *)args->args[0], // path
            (fd_t)args->args[1],                // dir
            (const char __user *)args->args[2], // link_name
            (unsigned long)args->args[2]        // flags
        );
        break;
    case SYSCALL_ID_UNLINK:
        ret_val = (uint64_t)(int)syscall_unlink(
            (fd_t)args->args[0],               // dir
            (const char __user *)args->args[1] // name
        );
        break;
    case SYSCALL_ID_CHROOT:
        ret_val = (uint64_t)(int)syscall_chroot((fd_t)args->args[0]);
        break;
    case SYSCALL_ID_PIPE:
        ret_val = (uint64_t)(int)syscall_pipe(
            (unsigned long)args->args[0], // flags
            (unsigned long)args->args[1], // mode_flags
            (fd_t __user *)args->args[2]);
        break;
    case SYSCALL_ID_INSMOD:
        ret_val =
            (uint64_t)(int)syscall_insmod((fd_t)args->args[0],
                                          (const char __user *)args->args[1],
                                          (unsigned long)args->args[2]);
        break;
    case SYSCALL_ID_RMMOD:
        ret_val =
            (uint64_t)(int)syscall_rmmod((const char __user *)args->args[0],
                                         (unsigned long)args->args[1]);
        break;
    case SYSCALL_ID_CHWDIR:
        ret_val = (uint64_t)(int)syscall_chwdir((fd_t)args->args[0]);
        break;
    case SYSCALL_ID_SLEEP:
        ret_val = (uint64_t)(int)syscall_sleep((size_t)args->args[0],
                                               (unsigned long)args->args[1]);
        break;
    case SYSCALL_ID_TIME:
        ret_val = (uint64_t)(ssize_t)syscall_time((unsigned long)args->args[0]);
        break;
    case SYSCALL_ID_RID:
        ret_val =
            (uint64_t)(int)syscall_rid((pid_t)args->args[0],         // target
                                       (unsigned long)args->args[1], // flags
                                       (id_t __user *)args->args[2]  // id_out
            );
        break;
    case SYSCALL_ID_WID:
        ret_val =
            (uint64_t)(int)syscall_wid((pid_t)args->args[0],         // target
                                       (unsigned long)args->args[1], // flags
                                       (id_t)args->args[2]           // id
            );
        break;
    case SYSCALL_ID_RESIZE:
        ret_val =
            (uint64_t)(int)syscall_resize((fd_t)args->args[0],         // file
                                          (size_t)args->args[1],       // size
                                          (unsigned long)args->args[2] // flags
            );
        break;
    case SYSCALL_ID_POLL:
        ret_val = (uint64_t)(int)syscall_poll(
            (fd_t)args->args[0],                  // file
            (unsigned long)args->args[1],         // watching
            (unsigned long __user *)args->args[2] // triggered
        );
        break;
    case SYSCALL_ID_SIGSEND:
        ret_val =
            (uint64_t)(int)syscall_sigsend((pid_t)args->args[0], // target
                                           (int)args->args[1],   // signal
                                           (unsigned long)args->args[2] // flags
            );
        break;
    case SYSCALL_ID_SIGINFO:
        ret_val = (uint64_t)(int)syscall_siginfo(
            (unsigned long)args->args[0],
            (unsigned long __user *)args->args[1]);
        break;
    case SYSCALL_ID_SIGMOD:
        ret_val = (uint64_t)(int)syscall_sigmod((unsigned long)args->args[0],
                                                (unsigned long)args->args[1]);
        break;
    case SYSCALL_ID_PRGET:
        ret_val =
            (uint64_t)(int)syscall_prget((unsigned long)args->args[0],
                                         (long)args->args[1],
                                         (unsigned long __user *)args->args[2]);
        break;
    case SYSCALL_ID_PRSET:
        ret_val = (uint64_t)(int)syscall_prset((unsigned long)args->args[0],
                                               (long)args->args[1],
                                               (unsigned long)args->args[2]);
        break;
    case SYSCALL_ID_ACCEPT:
        ret_val = (uint64_t)(int)syscall_accept((fd_t)args->args[0],
                                                (fd_t __user *)args->args[1],
                                                (unsigned long)args->args[2]);
        break;
    case SYSCALL_ID_CONNECT:
        ret_val = (uint64_t)(int)syscall_connect((fd_t)args->args[0],
                                                 (fd_t __user *)args->args[1],
                                                 (unsigned long)args->args[2]);
        break;
    case SYSCALL_ID_SOCKET:
        ret_val = (uint64_t)(int)syscall_socket((unsigned long)args->args[0],
                                                (unsigned long)args->args[1],
                                                (fd_t __user *)args->args[2]);
        break;
    default:
        syscall_unknown(id);
        ret_val = -ENOSYS;
        break;
    }

    DEBUG_ASSERT_MSG(irqs_enabled(),
                     "Returned from syscall (%s) with IRQ's disabled!",
                     syscall_id_string(id));

#ifdef CONFIG_STRACE_TIME_SYSCALLS
    time_t __end_time = current_timestamp();
    duration_t __handler_duration = __end_time - __start_time;

    switch(id)
    {
    case SYSCALL_ID_SLEEP:
        break;
    default:
        printk("syscall [%s] took %lld ms\n",
               syscall_id_string(id),
               duration_to_msec(__handler_duration));
        break;
    }
#endif
    strace_end_syscall(process, id);

    *ret_out = ret_val;

    return 0;
}

const char *
syscall_id_string(syscall_id_t id)
{
    const char *str;
    switch(id)
    {
#define SYSCALL_ID_STR_CASE(__name, __id, __NAME, ...)                         \
    case __id:                                                                 \
        str = #__name;                                                         \
        break;
    default:
        str = "Unknown";
        break;
        SYSCALL_XLIST(SYSCALL_ID_STR_CASE)
#undef SYSCALL_ID_STR_CASE
    }
    return str;
}
