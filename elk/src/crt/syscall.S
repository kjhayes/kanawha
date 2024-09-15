
.code64
.text

#define SYSCALL_ID_EXIT      0
#define SYSCALL_ID_OPEN      1
#define SYSCALL_ID_CLOSE     2
#define SYSCALL_ID_READ      3
#define SYSCALL_ID_WRITE     4
#define SYSCALL_ID_SEEK      5
#define SYSCALL_ID_ATTR      6
#define SYSCALL_ID_MMAP      7
#define SYSCALL_ID_MUNMAP    8
#define SYSCALL_ID_EXEC      9
#define SYSCALL_ID_ENVIRON   10
#define SYSCALL_ID_CHILDNAME 11
#define SYSCALL_ID_SPAWN     12
#define SYSCALL_ID_REAP      13
#define SYSCALL_ID_GETPID    14
#define SYSCALL_ID_MOUNT     15
#define SYSCALL_ID_UNMOUNT   16
#define SYSCALL_ID_DIRBEGIN  17
#define SYSCALL_ID_DIRNEXT   18
#define SYSCALL_ID_DIRATTR   19
#define SYSCALL_ID_DIRNAME   20

.global sys_exit
.type sys_exit,@function
sys_exit:
    movq $SYSCALL_ID_EXIT, %rax
    // rdi -> exitcode
    syscall
    retq

.global sys_open
.type sys_open,@function
sys_open:
    movq $SYSCALL_ID_OPEN, %rax
    // rdi -> const char * name
    // rsi -> unsigned long access_flags
    // rdx -> unsigned long mode_flags
    movq %rcx, %r8 // r8 -> fd_t *fd_out
    syscall
    retq

.global sys_close
.type sys_close,@function
sys_close:
    movq $SYSCALL_ID_CLOSE, %rax
    // rdi -> fd_t file
    syscall
    retq

.global sys_read
.type sys_read,@function
sys_read:
    movq $SYSCALL_ID_READ, %rax
    // rdi -> fd_t file
    // rsi -> void * dst
    // rdx -> size_t size 
    syscall
    retq

.global sys_write
.type sys_write,@function
sys_write:
    movq $SYSCALL_ID_WRITE, %rax
    // rdi -> fd_t file
    // rsi -> void *src
    // rdx -> size_t size
    syscall
    retq

.global sys_seek
.type sys_seek,@function
sys_seek:
    movq $SYSCALL_ID_SEEK, %rax
    // rdi -> fd_t file
    // rsi -> size_t offset
    // rdx -> int whence 
    syscall
    retq

.global sys_attr
.type sys_attr,@function
sys_attr:
    movq $SYSCALL_ID_ATTR, %rax
    // rdi -> fd_t file
    // rsi -> int attr 
    // rdx -> size_t __user * value 
    syscall
    retq

.global sys_mmap
.type sys_mmap,@function
sys_mmap:
    movq $SYSCALL_ID_MMAP, %rax
    // rdi -> fd_t file
    // rsi -> size_t file_offset
    // rdx -> void * where
    // Need to do these backwards
    movq %r9, %r10 // r10 -> unsigned long mmap_flags
    movq %r8, %r9  // r9 -> unsigned long prot_flags
    movq %rcx, %r8 // r8 -> size_t size
    syscall
    retq

.global sys_munmap
.type sys_munmap,@function
sys_munmap:
    movq $SYSCALL_ID_MUNMAP, %rax
    // rdi -> void * mapping
    syscall
    retq

.global sys_exec
.type sys_exec,@function
sys_exec:
    movq $SYSCALL_ID_EXEC, %rax
    // rdi -> fd_t file
    // rsi -> unsigned long exec_flags
    syscall
    retq

.global sys_environ
.type sys_environ,@function
sys_environ:
    movq $SYSCALL_ID_ENVIRON, %rax
    // rdi -> const char *key
    // rsi -> char *value
    // rdx -> size_t len
    movq %rcx, %r8 // %r8 -> int opcode
    syscall
    retq

.global sys_childname
.type sys_childname,@function
sys_childname:
    movq $SYSCALL_ID_CHILDNAME, %rax
    // rdi -> fd_t parent
    // rsi -> size_t child_index
    // rdx -> char *name_buf
    movq %rcx, %r8 // %r8 -> size_t buf_len
    syscall
    retq

.global sys_spawn
.type sys_spawn,@function
sys_spawn:
    movq $SYSCALL_ID_SPAWN, %rax
    // rdi -> void *entry 
    // rsi -> void *arg
    // rdx -> unsigned long flags 
    movq %rcx, %r8 // r8 -> pid_t *child_pid
    syscall
    retq

.global sys_reap
.type sys_reap,@function
sys_reap:
    movq $SYSCALL_ID_REAP, %rax
    // rdi -> pid_t child 
    // rsi -> unsigned long flags
    // rdx -> int *exitcode 
    syscall
    retq

.global sys_getpid
.type sys_getpid,@function
sys_getpid:
    movq $SYSCALL_ID_GETPID, %rax
    syscall
    retq

.global sys_mount
.type sys_mount,@function
sys_mount:
    movq $SYSCALL_ID_MOUNT, %rax
    // rdi -> const char *source
    // rsi -> fd_t dest_dir 
    // rdx -> const char *dest_name
    // Need to do these backwards
    movq %r8, %r9  // r9 -> unsigned long flags
    movq %rcx, %r8 // r8 -> const char *fs_type
    syscall
    retq

.global sys_unmount
.type sys_unmount,@function
sys_unmount:
    movq $SYSCALL_ID_UNMOUNT, %rax
    // rdi -> fd_t mount_point
    syscall
    retq

.global sys_dirbegin
.type sys_dirbegin,@function
sys_dirbegin:
    movq $SYSCALL_ID_DIRBEGIN, %rax
    // rdi -> fd_t dir 
    syscall
    retq

.global sys_dirnext
.type sys_dirnext,@function
sys_dirnext:
    movq $SYSCALL_ID_DIRNEXT, %rax
    // rdi -> fd_t dir 
    syscall
    retq

.global sys_dirattr
.type sys_dirattr,@function
sys_dirattr:
    movq $SYSCALL_ID_DIRATTR, %rax
    // rdi -> fd_t dir 
    // rsi -> int attr
    // rdx -> size_t *value
    syscall
    retq

.global sys_dirname
.type sys_dirname,@function
sys_dirname:
    movq $SYSCALL_ID_DIRNAME, %rax
    // rdi -> fd_t dir 
    // rsi -> char *buffer
    // rdx -> size_t buffer_len
    syscall
    retq

