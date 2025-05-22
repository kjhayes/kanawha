
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/strace.h>
#include <kanawha/irq.h>

#define __KANAWHA_SYSCALL_KEEP_XLIST
#include <kanawha/uapi/syscall.h>

int
syscall_unknown(
        struct process *process,
        syscall_id_t id)
{
    eprintk("process(%ld) Unknown syscall (%ld)\n",
            (sl_t)process->id,
            (sl_t)id);
    return 0;
}

int
handle_syscall(
        syscall_id_t id,
        struct syscall_args *args,
        uint64_t *ret_out)
{
    uint64_t ret_val;

    struct process *process = current_process();

    DEBUG_ASSERT_MSG(irqs_enabled(), "Handling syscall with IRQ(s) disabled!");

    DEBUG_ASSERT_FS_PATH_VALID(process->working_directory);
    DEBUG_ASSERT_FS_PATH_VALID(process->root_directory);

    strace_begin_syscall(process, id);

    switch(id) {
        case SYSCALL_ID_EXIT:
            syscall_exit(process, args->args[0]);
            break;
        case SYSCALL_ID_OPEN:
            ret_val = (uint64_t)(fd_t)
                syscall_open(
                        process,
                        (const char __user *)args->args[0], // path
                        (unsigned long)args->args[1], // access_flags
                        (unsigned long)args->args[2], // mode_flags
                        (fd_t __user *)args->args[3] // fd_out
                        );
            break;
        case SYSCALL_ID_CLOSE:
            ret_val = (int)
                syscall_close(
                        process,
                        (fd_t)args->args[0]);
            break;
        case SYSCALL_ID_READ:
            ret_val = (uint64_t)(ssize_t)
                syscall_read(
                        process,
                        (fd_t)args->args[0], // file
                        (void __user *)args->args[1], // dst
                        (size_t)args->args[2] // size
                        );
            break;
        case SYSCALL_ID_WRITE:
            ret_val = (uint64_t)(ssize_t)
                syscall_write(
                        process,
                        (fd_t)args->args[0], // file
                        (void __user *)args->args[1], // src
                        (size_t)args->args[2] // size
                        );
            break;
        case SYSCALL_ID_FLUSH:
            ret_val = (uint64_t)(int)
                syscall_flush(
                        process,
                        (fd_t)args->args[0], // file
                        (unsigned long)args->args[1] // flags
                        );
            break;
        case SYSCALL_ID_SEEK:
            ret_val = (uint64_t)(ssize_t)
                syscall_seek(
                        process,
                        (fd_t)args->args[0], // file
                        (ssize_t)args->args[1], // offset
                        (int)args->args[2] // whence
                        );
            break;
        case SYSCALL_ID_MMAP:
            ret_val = (uint64_t)(int)
                syscall_mmap(
                        process,
                        (fd_t)args->args[0], // file
                        (size_t)args->args[1], // file offset
                        (void __user * __user *)args->args[2], // where
                        (size_t)args->args[3], // size
                        (unsigned long)args->args[4] // mmap_flags
                        );
            break;
        case SYSCALL_ID_MUNMAP:
            ret_val = (uint64_t)(int)
                syscall_munmap(
                        process,
                        (void __user *)args->args[0] // mapping
                        );
            break;
        case SYSCALL_ID_EXEC:
            ret_val = (uint64_t)(int)
                syscall_exec(
                        process,
                        (fd_t)args->args[0], // file
                        (unsigned long)args->args[1] // exec_flags
                        );
            break;
        case SYSCALL_ID_GETCWD:
            ret_val = (uint64_t)(int)
                syscall_getcwd(
                        process,
                        (char __user *)args->args[0], // buffer
                        (size_t)args->args[1] // buflen
                        );
            break;
        case SYSCALL_ID_ENVIRON:
            ret_val = (uint64_t)(int)
                syscall_environ(
                        process,
                        (const char __user *)args->args[0], // key
                        (char __user *)args->args[1], // value
                        (size_t)args->args[2], // len
                        (int)args->args[3] // operation
                        );
            break;
        case SYSCALL_ID_SPAWN:
            ret_val = (uint64_t)(int)
                syscall_spawn(
                        process,
                        (void __user *)args->args[0], // entry
                        (void *)args->args[1], // arg
                        (unsigned long)args->args[2], // flags
                        (pid_t __user *)args->args[3] // child
                        );
            break;
        case SYSCALL_ID_REAP:
            ret_val = (uint64_t)(int)
                syscall_reap(
                        process,
                        (unsigned long)args->args[0], // flags
                        (pid_t __user *)args->args[1], // pid_inout
                        (int __user *)args->args[2] // exitcode
                        );
            break;
        case SYSCALL_ID_GETPID:
            ret_val = (uint64_t)(pid_t)
                syscall_getpid(
                        process
                        );
            break;
        case SYSCALL_ID_MOUNT:
            ret_val = (uint64_t)(int)
                syscall_mount(
                        process,
                        (const char __user *)args->args[0], // source
                        (fd_t)args->args[1], // dst_dir
                        (const char __user *)args->args[2], // dst_name
                        (const char __user *)args->args[3], // fs_type
                        (unsigned long)args->args[4] // flags
                        );
            break;
        case SYSCALL_ID_UNMOUNT:
            ret_val = (uint64_t)(int)
                syscall_unmount(
                        process,
                        (fd_t)args->args[0] // mount point
                        );
            break;
       case SYSCALL_ID_DIRBEGIN:
            ret_val = (uint64_t)(int)
                syscall_dirbegin(
                        process,
                        (fd_t)args->args[0] // dir
                        );
            break;
       case SYSCALL_ID_DIRNEXT:
            ret_val = (uint64_t)(int)
                syscall_dirnext(
                        process,
                        (fd_t)args->args[0] // dir
                        );
            break;
       case SYSCALL_ID_DIRATTR:
            ret_val = (uint64_t)(int)
                syscall_dirattr(
                        process,
                        (fd_t)args->args[0], // mount point
                        (int)args->args[1], // attr
                        (size_t __user *)args->args[2] // value
                        );
            break;
       case SYSCALL_ID_DIRNAME:
            ret_val = (uint64_t)(int)
                syscall_dirname(
                        process,
                        (fd_t)args->args[0], // mount point
                        (char __user *)args->args[1], // buffer
                        (size_t)args->args[2] // buflen
                        );
            break;
        case SYSCALL_ID_FMOVE:
            ret_val = (uint64_t)(int)
                syscall_fmove(
                        process,
                        (fd_t)args->args[0], // fd0
                        (fd_t)args->args[1],  // fd1
                        (unsigned long)args->args[2], // flags
                        (fd_t __user *)args->args[3] // out
                        );
            break;
        case SYSCALL_ID_FATTR:
            ret_val = (uint64_t)(int)
                syscall_fattr(
                        process,
                        (fd_t)args->args[0],
                        (int)args->args[1],
                        (size_t __user *)args->args[2]
                        );
            break;
        case SYSCALL_ID_MKFILE:
            ret_val = (uint64_t)(int)
                syscall_mkfile(
                        process,
                        (fd_t)args->args[0], // dir
                        (const char __user *)args->args[1], // file_name
                        (unsigned long)args->args[2] 
                        );
            break;
        case SYSCALL_ID_MKDIR:
            ret_val = (uint64_t)(int)
                syscall_mkdir(
                        process,
                        (fd_t)args->args[0], // dir
                        (const char __user *)args->args[1], // name
                        (unsigned long)args->args[2] // flags
                        );
            break;
        case SYSCALL_ID_LINK:
            ret_val = (uint64_t)(int)
                syscall_link(
                        process,
                        (fd_t)args->args[0], // from
                        (fd_t)args->args[1], // dir
                        (const char __user *)args->args[2], // link_name
                        (unsigned long)args->args[3] // flags
                        );
            break;
        case SYSCALL_ID_SYMLINK:
            ret_val = (uint64_t)(int)
                syscall_symlink(
                        process,
                        (const char __user *)args->args[0], // path
                        (fd_t)args->args[1], // dir
                        (const char __user *)args->args[2], // link_name
                        (unsigned long)args->args[2] // flags
                        );
            break;
        case SYSCALL_ID_UNLINK:
            ret_val = (uint64_t)(int)
                syscall_unlink(
                        process,
                        (fd_t)args->args[0], // dir
                        (const char __user *)args->args[1] // name
                        );
            break;
        case SYSCALL_ID_CHROOT:
            ret_val = (uint64_t)(int)
                syscall_chroot(
                        process,
                        (fd_t)args->args[0]
                        );
            break;
        case SYSCALL_ID_PIPE:
            ret_val = (uint64_t)(int)
                syscall_pipe(
                        process,
                        (unsigned long)args->args[0],
                        (fd_t __user *)args->args[1]
                        );
            break;
        case SYSCALL_ID_INSMOD:
            ret_val = (uint64_t)(int)
                syscall_insmod(
                        process,
                        (fd_t)args->args[0],
                        (const char __user *)args->args[1],
                        (unsigned long)args->args[2]
                        );
            break;
        case SYSCALL_ID_RMMOD:
            ret_val = (uint64_t)(int)
                syscall_rmmod(
                        process,
                        (const char __user *)args->args[0],
                        (unsigned long)args->args[1]
                        );
            break;
        case SYSCALL_ID_CHWDIR:
            ret_val = (uint64_t)(int)
                syscall_chwdir(
                        process,
                        (fd_t)args->args[0]
                        );
            break;
        case SYSCALL_ID_SLEEP:
            ret_val = (uint64_t)(int)
                syscall_sleep(
                        process,
                        (size_t)args->args[0],
                        (unsigned long)args->args[1]
                        );
            break;
        case SYSCALL_ID_TIME:
            ret_val = (uint64_t)(ssize_t)
                syscall_time(
                        process,
                        (unsigned long)args->args[0]
                        );
            break;
        case SYSCALL_ID_SIGRET:
            ret_val = (uint64_t)(int)
                syscall_sigret(
                        process
                        );
            break;
        case SYSCALL_ID_SIGROUTE:
            ret_val = (uint64_t)(int)
                syscall_sigroute(
                        process,
                        (void __user *)args->args[0]
                        );
            break;
        case SYSCALL_ID_RID:
            ret_val = (uint64_t)(int)
                syscall_rid(
                        process,
                        (pid_t)args->args[0], // target
                        (unsigned long)args->args[1], // flags
                        (id_t __user *)args->args[2] // id_out
                        );
            break;
        case SYSCALL_ID_WID:
            ret_val = (uint64_t)(int)
                syscall_wid(
                        process,
                        (pid_t)args->args[0], // target
                        (unsigned long)args->args[1], // flags
                        (id_t)args->args[2] // id
                        );
            break;
        case SYSCALL_ID_RESIZE:
            ret_val = (uint64_t)(int)
                syscall_resize(
                        process,
                        (fd_t)args->args[0], // file
                        (size_t)args->args[1], // size 
                        (unsigned long)args->args[2] // flags
                        );
            break;
        case SYSCALL_ID_POLL:
            ret_val = (uint64_t)(int)
                syscall_poll(
                        process,
                        (fd_t)args->args[0], // file
                        (unsigned long)args->args[1], // watching
                        (unsigned long __user *)args->args[2] // triggered
                        );
            break;
        default:
            syscall_unknown(process, id);
            ret_val = -EINVAL;
    }

    DEBUG_ASSERT_MSG(irqs_enabled(), "Returned from syscall (%s) with IRQ's disabled!", syscall_id_string(id));

    strace_end_syscall(process, id);

    *ret_out = ret_val;

    return 0;
}

const char *
syscall_id_string(
        syscall_id_t id)
{
    const char *str;
    switch(id) {
#define SYSCALL_ID_STR_CASE(__name, __id, __NAME, ...)\
        case __id:\
            str = #__name;\
            break;
        default:
            str = "Unknown";
            break;
SYSCALL_XLIST(SYSCALL_ID_STR_CASE)
#undef SYSCALL_ID_STR_CASE
    }
    return str;
}

