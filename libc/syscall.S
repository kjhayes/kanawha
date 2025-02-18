
.code64
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
#define KANAWHA_SYSCALL_ID_MKFILE    22
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
    movq $KANAWHA_SYSCALL_ID_EXIT, %rax
    // rdi -> exitcode
    syscall
    retq

.global kanawha_sys_open
.type kanawha_sys_open,@function
kanawha_sys_open:
    movq $KANAWHA_SYSCALL_ID_OPEN, %rax
    // rdi -> const char * name
    // rsi -> unsigned long access_flags
    // rdx -> unsigned long mode_flags
    movq %rcx, %r8 // r8 -> fd_t *fd_out
    syscall
    retq

.global kanawha_sys_close
.type kanawha_sys_close,@function
kanawha_sys_close:
    movq $KANAWHA_SYSCALL_ID_CLOSE, %rax
    // rdi -> fd_t file
    syscall
    retq

.global kanawha_sys_read
.type kanawha_sys_read,@function
kanawha_sys_read:
    movq $KANAWHA_SYSCALL_ID_READ, %rax
    // rdi -> fd_t file
    // rsi -> void * dst
    // rdx -> size_t size 
    syscall
    retq

.global kanawha_sys_write
.type kanawha_sys_write,@function
kanawha_sys_write:
    movq $KANAWHA_SYSCALL_ID_WRITE, %rax
    // rdi -> fd_t file
    // rsi -> void *src
    // rdx -> size_t size
    syscall
    retq

.global kanawha_sys_seek
.type kanawha_sys_seek,@function
kanawha_sys_seek:
    movq $KANAWHA_SYSCALL_ID_SEEK, %rax
    // rdi -> fd_t file
    // rsi -> size_t offset
    // rdx -> int whence 
    syscall
    retq

.global kanawha_sys_flush
.type kanawha_sys_flush,@function
kanawha_sys_flush:
    movq $KANAWHA_SYSCALL_ID_FLUSH, %rax
    // rdi -> fd_t file
    // rsi -> unsigned long flags
    syscall
    retq

.global kanawha_sys_mmap
.type kanawha_sys_mmap,@function
kanawha_sys_mmap:
    movq $KANAWHA_SYSCALL_ID_MMAP, %rax
    // rdi -> ad_t aspace
    // rsi -> fd_t file
    // rdx -> size_t file_offset
    // Need to do these backwards
    movq %r9, %r10 // r10 -> unsigned long flags
    movq %r8, %r9  // r9 -> size_t size
    movq %rcx, %r8 // r8 -> void **where
    syscall
    retq

.global kanawha_sys_munmap
.type kanawha_sys_munmap,@function
kanawha_sys_munmap:
    movq $KANAWHA_SYSCALL_ID_MUNMAP, %rax
    // rdi -> ad_t aspace
    // rsi -> void * mapping
    syscall
    retq

.global kanawha_sys_exec
.type kanawha_sys_exec,@function
kanawha_sys_exec:
    movq $KANAWHA_SYSCALL_ID_EXEC, %rax
    // rdi -> fd_t file
    // rsi -> unsigned long exec_flags
    syscall
    retq

.global kanawha_sys_environ
.type kanawha_sys_environ,@function
kanawha_sys_environ:
    movq $KANAWHA_SYSCALL_ID_ENVIRON, %rax
    // rdi -> const char *key
    // rsi -> char *value
    // rdx -> size_t len
    movq %rcx, %r8 // %r8 -> int opcode
    syscall
    retq

.global kanawha_sys_childname
.type kanawha_sys_childname,@function
kanawha_sys_childname:
    movq $KANAWHA_SYSCALL_ID_CHILDNAME, %rax
    // rdi -> fd_t parent
    // rsi -> size_t child_index
    // rdx -> char *name_buf
    movq %rcx, %r8 // %r8 -> size_t buf_len
    syscall
    retq

.global kanawha_sys_spawn
.type kanawha_sys_spawn,@function
kanawha_sys_spawn:
    movq $KANAWHA_SYSCALL_ID_SPAWN, %rax
    // rdi -> void *entry 
    // rsi -> void *arg
    // rdx -> unsigned long flags 
    movq %rcx, %r8 // r8 -> pid_t *child_pid
    syscall
    retq

.global kanawha_sys_reap
.type kanawha_sys_reap,@function
kanawha_sys_reap:
    movq $KANAWHA_SYSCALL_ID_REAP, %rax
    // rdi -> pid_t child 
    // rsi -> unsigned long flags
    // rdx -> int *exitcode 
    syscall
    retq

.global kanawha_sys_getpid
.type kanawha_sys_getpid,@function
kanawha_sys_getpid:
    movq $KANAWHA_SYSCALL_ID_GETPID, %rax
    syscall
    retq

.global kanawha_sys_mount
.type kanawha_sys_mount,@function
kanawha_sys_mount:
    movq $KANAWHA_SYSCALL_ID_MOUNT, %rax
    // rdi -> const char *source
    // rsi -> fd_t dest_dir 
    // rdx -> const char *dest_name
    // Need to do these backwards
    movq %r8, %r9  // r9 -> unsigned long flags
    movq %rcx, %r8 // r8 -> const char *fs_type
    syscall
    retq

.global kanawha_sys_unmount
.type kanawha_sys_unmount,@function
kanawha_sys_unmount:
    movq $KANAWHA_SYSCALL_ID_UNMOUNT, %rax
    // rdi -> fd_t mount_point
    syscall
    retq

.global kanawha_sys_dirbegin
.type kanawha_sys_dirbegin,@function
kanawha_sys_dirbegin:
    movq $KANAWHA_SYSCALL_ID_DIRBEGIN, %rax
    // rdi -> fd_t dir 
    syscall
    retq

.global kanawha_sys_dirnext
.type kanawha_sys_dirnext,@function
kanawha_sys_dirnext:
    movq $KANAWHA_SYSCALL_ID_DIRNEXT, %rax
    // rdi -> fd_t dir 
    syscall
    retq

.global kanawha_sys_dirattr
.type kanawha_sys_dirattr,@function
kanawha_sys_dirattr:
    movq $KANAWHA_SYSCALL_ID_DIRATTR, %rax
    // rdi -> fd_t dir 
    // rsi -> int attr
    // rdx -> size_t *value
    syscall
    retq

.global kanawha_sys_dirname
.type kanawha_sys_dirname,@function
kanawha_sys_dirname:
    movq $KANAWHA_SYSCALL_ID_DIRNAME, %rax
    // rdi -> fd_t dir 
    // rsi -> char *buffer
    // rdx -> size_t buffer_len
    syscall
    retq

.global kanawha_sys_fmove
.type kanawha_sys_fmove,@function
kanawha_sys_fmove:
    movq $KANAWHA_SYSCALL_ID_FMOVE, %rax
    // rdi -> fd_t f0
    // rsi -> fd_t f1
    // rdx -> unsigned long flags
    movq %rcx, %r8 // r8 -> fd_t *out
    syscall
    retq

.global kanawha_sys_mkfile
.type kanawha_sys_mkfile,@function
kanawha_sys_mkfile:
    movq $KANAWHA_SYSCALL_ID_MKFILE, %rax
    // rdi -> fd_t dir
    // rsi -> const char *file_name
    // rdx -> unsigned long flags
    syscall
    retq

.global kanawha_sys_mkdir
.type kanawha_sys_mkdir,@function
kanawha_sys_mkdir:
    movq $KANAWHA_SYSCALL_ID_MKDIR, %rax
    // rdi -> fd_t dir
    // rsi -> const char *name
    // rdx -> unsigned long flags
    syscall
    retq

.global kanawha_sys_link
.type kanawha_sys_link,@function
kanawha_sys_link:
    movq $KANAWHA_SYSCALL_ID_LINK, %rax
    // rdi -> fd_t from
    // rdi -> fd_t dir
    // rsi -> const char *link_name
    movq %rcx, %r8 // r8 -> unsigned long flags
    syscall
    retq

.global kanawha_sys_symlink
.type kanawha_sys_symlink,@function
kanawha_sys_symlink:
    movq $KANAWHA_SYSCALL_ID_SYMLINK, %rax
    // rdi -> const char *sym_path
    // rdi -> fd_t dir
    // rsi -> const char *symlink_name
    movq %rcx, %r8 // r8 -> unsigned long flags
    syscall
    retq

.global kanawha_sys_unlink
.type kanawha_sys_unlink,@function
kanawha_sys_unlink:
    movq $KANAWHA_SYSCALL_ID_UNLINK, %rax
    // rdi -> fd_t dir
    // rsi -> const char *name
    syscall
    retq

.global kanawha_sys_chroot
.type kanawha_sys_chroot,@function
kanawha_sys_chroot:
    movq $KANAWHA_SYSCALL_ID_CHROOT, %rax
    // rdi -> fd_t dir
    syscall
    retq

.global kanawha_sys_pipe
.type kanawha_sys_pipe,@function
kanawha_sys_pipe:
    movq $KANAWHA_SYSCALL_ID_PIPE, %rax
    // rdi -> unsigned long flags
    // rsi -> fd_t *out
    syscall
    retq

.global kanawha_sys_insmod
.type kanawha_sys_insmod,@function
kanawha_sys_insmod:
    movq $KANAWHA_SYSCALL_ID_INSMOD, %rax
    // rdi -> fd_t file
    // rsi -> const char *modname
    // rdx -> unsigned long flags
    syscall
    retq

.global kanawha_sys_rmmod
.type kanawha_sys_rmmod,@function
kanawha_sys_rmmod:
    movq $KANAWHA_SYSCALL_ID_RMMOD, %rax
    // rdi -> const char *modname
    // rsi -> unsigned long flags
    syscall
    retq

.global kanawha_sys_chwdir
.type kanawha_sys_chwdir,@function
kanawha_sys_chwdir:
    movq $KANAWHA_SYSCALL_ID_CHWDIR, %rax
    // rdi -> fd_t dir
    syscall
    retq

.global kanawha_sys_sleep
.type kanawha_sys_sleep,@function
kanawha_sys_sleep:
    movq $KANAWHA_SYSCALL_ID_SLEEP, %rax
    // rdi -> size_t duration
    // rsi -> unsigned long flags
    syscall
    retq

.global kanawha_sys_time
.type kanawha_sys_time,@function
kanawha_sys_time:
    movq $KANAWHA_SYSCALL_ID_TIME, %rax
    // rdi -> unsigned long flags
    syscall
    retq

.global kanawha_sys_sigret
.type kanawha_sys_sigret,@function
kanawha_sys_sigret:
    movq $KANAWHA_SYSCALL_ID_SIGRET, %rax
    syscall
    retq

.global kanawha_sys_sigroute
.type kanawha_sys_sigroute,@function
kanawha_sys_sigroute:
    movq $KANAWHA_SYSCALL_ID_SIGROUTE, %rax
    // rdi -> void * entry
    syscall
    retq

