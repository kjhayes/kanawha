
.text

#define KANAWHA_SYSCALL_ID_EXIT      0
#define KANAWHA_SYSCALL_ID_OPEN      1
#define KANAWHA_SYSCALL_ID_CLOSE     2
#define KANAWHA_SYSCALL_ID_READ      3
#define KANAWHA_SYSCALL_ID_WRITE     4
#define KANAWHA_SYSCALL_ID_SEEK      5
#define KANAWHA_SYSCALL_ID_FLUSH     6
#define KANAWHA_SYSCALL_ID_MMAP      7
#define KANAWHA_SYSCALL_ID_MUNMAP    8
#define KANAWHA_SYSCALL_ID_EXEC      9
#define KANAWHA_SYSCALL_ID_ENVIRON   10
#define KANAWHA_SYSCALL_ID_CHILDNAME 11
#define KANAWHA_SYSCALL_ID_SPAWN     12
#define KANAWHA_SYSCALL_ID_REAP      13
#define KANAWHA_SYSCALL_ID_GETPID    14
#define KANAWHA_SYSCALL_ID_MOUNT     15
#define KANAWHA_SYSCALL_ID_UNMOUNT   16
#define KANAWHA_SYSCALL_ID_DIRBEGIN  17
#define KANAWHA_SYSCALL_ID_DIRNEXT   18
#define KANAWHA_SYSCALL_ID_DIRATTR   19
#define KANAWHA_SYSCALL_ID_DIRNAME   20
#define KANAWHA_SYSCALL_ID_FMOVE     21
#define KANAWHA_SYSCALL_ID_FATTR     22
#define KANAWHA_SYSCALL_ID_MKFILE    23
#define KANAWHA_SYSCALL_ID_MKDIR     24
#define KANAWHA_SYSCALL_ID_LINK      25
#define KANAWHA_SYSCALL_ID_SYMLINK   26
#define KANAWHA_SYSCALL_ID_UNLINK    27
#define KANAWHA_SYSCALL_ID_CHROOT    28
#define KANAWHA_SYSCALL_ID_PIPE      29
#define KANAWHA_SYSCALL_ID_INSMOD    30
#define KANAWHA_SYSCALL_ID_RMMOD     31
#define KANAWHA_SYSCALL_ID_CHWDIR    32
#define KANAWHA_SYSCALL_ID_SLEEP     33
#define KANAWHA_SYSCALL_ID_TIME      34
#define KANAWHA_SYSCALL_ID_SIGRET    35
#define KANAWHA_SYSCALL_ID_SIGROUTE  36

.global kanawha_sys_exit
.type kanawha_sys_exit,@function
kanawha_sys_exit:
    li a7, KANAWHA_SYSCALL_ID_EXIT
    // a0 -> exitcode
    ecall
    ret

.global kanawha_sys_open
.type kanawha_sys_open,@function
kanawha_sys_open:
    li a7, KANAWHA_SYSCALL_ID_OPEN
    // a0 -> const char * name
    // a1 -> unsigned long access_flags
    // a2 -> unsigned long mode_flags
    // r8 -> fd_t *fd_out
    ecall
    ret

.global kanawha_sys_close
.type kanawha_sys_close,@function
kanawha_sys_close:
    li a7, KANAWHA_SYSCALL_ID_CLOSE
    // a0 -> fd_t file
    ecall
    ret

.global kanawha_sys_read
.type kanawha_sys_read,@function
kanawha_sys_read:
    li a7, KANAWHA_SYSCALL_ID_READ
    // a0 -> fd_t file
    // a1 -> void * dst
    // a2 -> size_t size 
    ecall
    ret

.global kanawha_sys_write
.type kanawha_sys_write,@function
kanawha_sys_write:
    li a7, KANAWHA_SYSCALL_ID_WRITE
    // a0 -> fd_t file
    // a1 -> void *src
    // a2 -> size_t size
    ecall
    ret

.global kanawha_sys_seek
.type kanawha_sys_seek,@function
kanawha_sys_seek:
    li a7, KANAWHA_SYSCALL_ID_SEEK
    // a0 -> fd_t file
    // a1 -> size_t offset
    // a2 -> int whence 
    ecall
    ret

.global kanawha_sys_flush
.type kanawha_sys_flush,@function
kanawha_sys_flush:
    li a7, KANAWHA_SYSCALL_ID_FLUSH
    // a0 -> fd_t file
    // a1 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_mmap
.type kanawha_sys_mmap,@function
kanawha_sys_mmap:
    li a7, KANAWHA_SYSCALL_ID_MMAP
    // a0 -> ad_t aspace
    // a1 -> fd_t file
    // a2 -> size_t file_offset
    // a3 -> void **where
    // a4 -> size_t size
    // a5 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_munmap
.type kanawha_sys_munmap,@function
kanawha_sys_munmap:
    li a7, KANAWHA_SYSCALL_ID_MUNMAP
    // a0 -> ad_t aspace
    // a1 -> void * mapping
    ecall
    ret

.global kanawha_sys_exec
.type kanawha_sys_exec,@function
kanawha_sys_exec:
    li a7, KANAWHA_SYSCALL_ID_EXEC
    // a0 -> fd_t file
    // a1 -> unsigned long exec_flags
    ecall
    ret

.global kanawha_sys_environ
.type kanawha_sys_environ,@function
kanawha_sys_environ:
    li a7, KANAWHA_SYSCALL_ID_ENVIRON
    // a0 -> const char *key
    // a1 -> char *value
    // a2 -> size_t len
    // a3 -> int opcode
    ecall
    ret

.global kanawha_sys_childname
.type kanawha_sys_childname,@function
kanawha_sys_childname:
    li a7, KANAWHA_SYSCALL_ID_CHILDNAME
    // a0 -> fd_t parent
    // a1 -> size_t child_index
    // a2 -> char *name_buf
    // a3 -> size_t buf_len
    ecall
    ret

.global kanawha_sys_spawn
.type kanawha_sys_spawn,@function
kanawha_sys_spawn:
    li a7, KANAWHA_SYSCALL_ID_SPAWN
    // a0 -> void *entry 
    // a1 -> void *arg
    // a2 -> unsigned long flags 
    // a3 -> pid_t *child_pid
    ecall
    ret

.global kanawha_sys_reap
.type kanawha_sys_reap,@function
kanawha_sys_reap:
    li a7, KANAWHA_SYSCALL_ID_REAP
    // a0 -> unsigned long flags
    // a1 -> pid_t *child_inout
    // a2 -> int *exitcode 
    ecall
    ret

.global kanawha_sys_getpid
.type kanawha_sys_getpid,@function
kanawha_sys_getpid:
    li a7, KANAWHA_SYSCALL_ID_GETPID
    ecall
    ret

.global kanawha_sys_mount
.type kanawha_sys_mount,@function
kanawha_sys_mount:
    li a7, KANAWHA_SYSCALL_ID_MOUNT
    // a0 -> const char *source
    // a1 -> fd_t dest_dir 
    // a2 -> const char *dest_name
    // a3 -> const char *fs_type
    // a4 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_unmount
.type kanawha_sys_unmount,@function
kanawha_sys_unmount:
    li a7, KANAWHA_SYSCALL_ID_UNMOUNT
    // a0 -> fd_t mount_point
    ecall
    ret

.global kanawha_sys_dirbegin
.type kanawha_sys_dirbegin,@function
kanawha_sys_dirbegin:
    li a7, KANAWHA_SYSCALL_ID_DIRBEGIN
    // a0 -> fd_t dir 
    ecall
    ret

.global kanawha_sys_dirnext
.type kanawha_sys_dirnext,@function
kanawha_sys_dirnext:
    li a7, KANAWHA_SYSCALL_ID_DIRNEXT
    // a0 -> fd_t dir 
    ecall
    ret

.global kanawha_sys_dirattr
.type kanawha_sys_dirattr,@function
kanawha_sys_dirattr:
    li a7, KANAWHA_SYSCALL_ID_DIRATTR
    // a0 -> fd_t dir 
    // a1 -> int attr
    // a2 -> size_t *value
    ecall
    ret

.global kanawha_sys_dirname
.type kanawha_sys_dirname,@function
kanawha_sys_dirname:
    li a7, KANAWHA_SYSCALL_ID_DIRNAME
    // a0 -> fd_t dir 
    // a1 -> char *buffer
    // a2 -> size_t buffer_len
    ecall
    ret

.global kanawha_sys_fmove
.type kanawha_sys_fmove,@function
kanawha_sys_fmove:
    li a7, KANAWHA_SYSCALL_ID_FMOVE
    // a0 -> fd_t f0
    // a1 -> fd_t f1
    // a2 -> unsigned long flags
    // a3 -> fd_t *out
    ecall
    ret

.global kanawha_sys_fattr
.type kanawha_sys_fattr,@function
kanawha_sys_fattr:
    li a7, KANAWHA_SYSCALL_ID_FATTR
    // a0 -> fd_t file
    // a1 -> int attr 
    // a2 -> size_t *out
    ecall
    ret

.global kanawha_sys_mkfile
.type kanawha_sys_mkfile,@function
kanawha_sys_mkfile:
    li a7, KANAWHA_SYSCALL_ID_MKFILE
    // a0 -> fd_t dir
    // a1 -> const char *file_name
    // a2 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_mkdir
.type kanawha_sys_mkdir,@function
kanawha_sys_mkdir:
    li a7, KANAWHA_SYSCALL_ID_MKDIR
    // a0 -> fd_t dir
    // a1 -> const char *name
    // a2 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_link
.type kanawha_sys_link,@function
kanawha_sys_link:
    li a7, KANAWHA_SYSCALL_ID_LINK
    // a0 -> fd_t from
    // a0 -> fd_t dir
    // a1 -> const char *link_name
    // a3 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_symlink
.type kanawha_sys_symlink,@function
kanawha_sys_symlink:
    li a7, KANAWHA_SYSCALL_ID_SYMLINK
    // a0 -> const char *sym_path
    // a1 -> fd_t dir
    // a2 -> const char *symlink_name
    // a3 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_unlink
.type kanawha_sys_unlink,@function
kanawha_sys_unlink:
    li a7, KANAWHA_SYSCALL_ID_UNLINK
    // a0 -> fd_t dir
    // a1 -> const char *name
    ecall
    ret

.global kanawha_sys_chroot
.type kanawha_sys_chroot,@function
kanawha_sys_chroot:
    li a7, KANAWHA_SYSCALL_ID_CHROOT
    // a0 -> fd_t dir
    ecall
    ret

.global kanawha_sys_pipe
.type kanawha_sys_pipe,@function
kanawha_sys_pipe:
    li a7, KANAWHA_SYSCALL_ID_PIPE
    // a0 -> unsigned long flags
    // a1 -> fd_t *out
    ecall
    ret

.global kanawha_sys_insmod
.type kanawha_sys_insmod,@function
kanawha_sys_insmod:
    li a7, KANAWHA_SYSCALL_ID_INSMOD
    // a0 -> fd_t file
    // a1 -> const char *modname
    // a2 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_rmmod
.type kanawha_sys_rmmod,@function
kanawha_sys_rmmod:
    li a7, KANAWHA_SYSCALL_ID_RMMOD
    // a0 -> const char *modname
    // a1 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_chwdir
.type kanawha_sys_chwdir,@function
kanawha_sys_chwdir:
    li a7, KANAWHA_SYSCALL_ID_CHWDIR
    // a0 -> fd_t dir
    ecall
    ret

.global kanawha_sys_sleep
.type kanawha_sys_sleep,@function
kanawha_sys_sleep:
    li a7, KANAWHA_SYSCALL_ID_SLEEP
    // a0 -> size_t duration
    // a1 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_time
.type kanawha_sys_time,@function
kanawha_sys_time:
    li a7, KANAWHA_SYSCALL_ID_TIME
    // a0 -> unsigned long flags
    ecall
    ret

.global kanawha_sys_sigret
.type kanawha_sys_sigret,@function
kanawha_sys_sigret:
    li a7, KANAWHA_SYSCALL_ID_SIGRET
    ecall
    ret

.global kanawha_sys_sigroute
.type kanawha_sys_sigroute,@function
kanawha_sys_sigroute:
    li a7, KANAWHA_SYSCALL_ID_SIGROUTE
    // a0 -> void * entry
    ecall
    ret

