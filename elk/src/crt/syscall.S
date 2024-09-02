
.code64
.text

.global exit
.type exit,@function
exit:
    movq $0, %rax
    // rdi -> exitcode
    syscall
    retq

.global open
.type open,@function
open:
    movq $1, %rax
    // rdi -> fd_t parent
    // rsi -> const char * name
    // rdx -> unsigned long access_flags
    // r8 -> unsigned long mode_flags
    movq %rcx, %r8
    syscall
    retq

.global close
.type close,@function
close:
    movq $2, %rax
    // rdi -> fd_t file
    syscall
    retq

.global read
.type read,@function
read:
    movq $3, %rax
    // rdi -> fd_t file
    // rsi -> void * dst
    // rdx -> size_t src_offset
    movq %rcx, %r8 // r8 -> size_t size
    syscall
    retq

.global write
.type write,@function
write:
    movq $4, %rax
    // rdi -> fd_t file
    // rsi -> size_t dst_offset
    // rdx -> void * src
    movq %rcx, %r8 // r8 -> size_t size
    syscall
    retq

.global mmap
.type mmap,@function
mmap:
    movq $5, %rax
    // rdi -> fd_t file
    // rsi -> size_t file_offset
    // rdx -> void * where
    // Need to do these backwards
    movq %r9, %r10 // r10 -> unsigned long mmap_flags
    movq %r8, %r9  // r9 -> unsigned long prot_flags
    movq %rcx, %r8 // r8 -> size_t size
    syscall
    retq

.global munmap
.type munmap,@function
munmap:
    movq $6, %rax
    // rdi -> void * mapping
    syscall
    retq

.global exec
.type exec,@function
exec:
    movq $7, %rax
    // rdi -> fd_t file
    // rsi -> unsigned long exec_flags
    syscall
    retq

.global environ
.type environ,@function
environ:
    movq $8, %rax
    // rdi -> const char *key
    // rsi -> char *value
    // rdx -> size_t len
    movq %rcx, %r8 // %r8 -> int opcode
    syscall
    retq

