
#include <kanawha/excp.h>
#include <kanawha/init.h>
#include <kanawha/usermode.h>
#include <kanawha/percpu.h>
#include <kanawha/vmem.h>
#include <kanawha/page_alloc.h>
#include <kanawha/syscall.h>
#include <kanawha/xcall.h>
#include <kanawha/process.h>
#include <kanawha/assert.h>
#include <arch/x64/msr.h>
#include <arch/x64/sysreg.h>
#include <arch/x64/gdt.h>
#include <arch/x64/asm/regs.S>

#define X64_SYSCALL_TRAMPOLINE_STACK_ORDER 14

// assembly routine to enter when syscall instruction is invoked
extern void x64_syscall_entry(void);
extern void x64_syscall_entry_compatibility_mode(void);

struct x64_syscall_trampoline
{
    void __user *user_return;
    void __user *user_stack;
    void *trampoline_stack_base;
} __attribute__((packed));

static DECLARE_PERCPU_VAR(struct x64_syscall_trampoline, x64_local_syscall_trampoline);
void __user * __percpu *x64_syscall_trampoline_percpu_ptr = PERCPU_NULL;

struct x64_syscall_state {
    uint64_t callee_regs[NUM_CALLEE_REGS];
    uint64_t caller_regs[NUM_CALLER_REGS];
    void __user *user_stack_ptr;
} __attribute__((packed));

void
x64_route_syscall(struct x64_syscall_state *state)
{
    enable_irqs();

    syscall_id_t id = state->caller_regs[PUSHED_CALLER_REGS_INDEX_RAX];
    void __user *user_return = (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RCX];
    uint64_t user_rflags = state->caller_regs[PUSHED_CALLER_REGS_INDEX_R11];

    uint64_t *ret_val = &state->caller_regs[PUSHED_CALLER_REGS_INDEX_RAX];

    dprintk("x64_route_syscall (id=%ld, user_return=0x%llx, user_rflags=0x%llx)\n",
            (sl_t)id, user_return, (uintptr_t)user_rflags);

    struct process *process = current_process();
    DEBUG_ASSERT(process);

    strace_begin_syscall(process, id);

    struct x64_syscall_trampoline *tramp = 
            percpu_ptr(percpu_addr(x64_local_syscall_trampoline));
    dprintk("TRAMPOLINE (user_stack=%p) (user_rip=%p) (trampoline_stack=%p)\n",
            tramp->user_stack,
            tramp->user_return,
            tramp->trampoline_stack_base);

    switch(id) {
        case SYSCALL_ID_EXIT:
            syscall_exit(process, state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI]);
            break;
        case SYSCALL_ID_OPEN:
            *ret_val = (uint64_t)(fd_t)
                syscall_open(
                        process,
                        (const char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // path
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // access_flags
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // mode_flags
                        (fd_t __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8] // fd_out
                        );
            break;
        case SYSCALL_ID_CLOSE:
            *ret_val = (int)
                syscall_close(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI]);
            break;
        case SYSCALL_ID_READ:
            *ret_val = (uint64_t)(ssize_t)
                syscall_read(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // dst
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX] // size
                        );
            break;
        case SYSCALL_ID_WRITE:
            *ret_val = (uint64_t)(ssize_t)
                syscall_write(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // src
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX] // size
                        );
            break;
        case SYSCALL_ID_SEEK:
            *ret_val = (uint64_t)(ssize_t)
                syscall_seek(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (ssize_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // offset
                        (int)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX] // whence
                        );
            break;
        case SYSCALL_ID_MMAP:
            *ret_val = (uint64_t)(int)
                syscall_mmap(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // file offset
                        (void __user * __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // where
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8], // size
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R9], // access_flags
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R10] // mmap_flags
                        );
            break;
        case SYSCALL_ID_MUNMAP:
            *ret_val = (uint64_t)(int)
                syscall_munmap(
                        process,
                        (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI] // mapping
                        );
            break;
        case SYSCALL_ID_EXEC:
            *ret_val = (uint64_t)(int)
                syscall_exec(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI] // exec_flags
                        );
            break;
        case SYSCALL_ID_ENVIRON:
            *ret_val = (uint64_t)(int)
                syscall_environ(
                        process,
                        (const char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // key
                        (char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // value
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // len
                        (int)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8] // operation
                        );
            break;
        case SYSCALL_ID_SPAWN:
            *ret_val = (uint64_t)(int)
                syscall_spawn(
                        process,
                        (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // entry
                        (void *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // arg
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // flags
                        (pid_t __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8] // child
                        );
            break;
        case SYSCALL_ID_REAP:
            *ret_val = (uint64_t)(int)
                syscall_reap(
                        process,
                        (pid_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // to_reap
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // flags
                        (int __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX] // exitcode
                        );
            break;
        case SYSCALL_ID_GETPID:
            *ret_val = (uint64_t)(pid_t)
                syscall_getpid(
                        process
                        );
            break;
        case SYSCALL_ID_MOUNT:
            *ret_val = (uint64_t)(int)
                syscall_mount(
                        process,
                        (const char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // source
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // dst_dir
                        (const char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // dst_name
                        (const char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8], // fs_type
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R9] // flags
                        );
            break;
        case SYSCALL_ID_UNMOUNT:
            *ret_val = (uint64_t)(int)
                syscall_unmount(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI] // mount point
                        );
            break;
       case SYSCALL_ID_DIRBEGIN:
            *ret_val = (uint64_t)(int)
                syscall_dirbegin(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI] // dir
                        );
            break;
       case SYSCALL_ID_DIRNEXT:
            *ret_val = (uint64_t)(int)
                syscall_dirnext(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI] // dir
                        );
            break;
       case SYSCALL_ID_DIRATTR:
            *ret_val = (uint64_t)(int)
                syscall_dirattr(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // mount point
                        (int)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // attr
                        (size_t __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX] // value
                        );
            break;
       case SYSCALL_ID_DIRNAME:
            *ret_val = (uint64_t)(int)
                syscall_dirname(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // mount point
                        (char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // buffer
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX] // buflen
                        );
            break;
        default:
            syscall_unknown(process, id);
    }

    strace_end_syscall(process, id);

    disable_irqs();

    if(process->forcing_ip) {
        state->caller_regs[PUSHED_CALLER_REGS_INDEX_RCX] =
            (uint64_t)process->forced_ip;
        process->forcing_ip = 0;
    }

    // We want to reset the kernel stack in-case we were preempted
    // when interrupts were enabled
    process->thread.arch_state.stack.rsp =
        process->thread.arch_state.stack.stack_base;

    return;
}

struct x64_syscall_setup_state {
    volatile int res;
    volatile int done;
};

// This can occur late because it just needs to happen before "launch"
static void
x64_setup_syscall_xcall(void *in)
{
    //printk("Setting up syscall Instruction on CPU (%ld)\n",
    //        (sl_t)current_cpu_id());

    struct x64_syscall_setup_state *state = in;
    
    // Enable syscall extensions in EFER
    write_msr(X64_MSR_EFER, read_msr(X64_MSR_EFER) | X64_EFER_SCE);

    // Weird restrictions of the "STAR" MSR
    if(X64_USER_DATA_GDT_SEGMENT_OFFSET + 8 != X64_USER_CODE_GDT_SEGMENT_OFFSET) {
        state->res = -EINVAL;
        state->done = 1;
        return;
    }
    if(X64_KERNEL_CODE_GDT_SEGMENT_OFFSET + 8 != X64_KERNEL_DATA_GDT_SEGMENT_OFFSET) {
        state->res = -EINVAL;
        state->done = 1;
        return;
    }

    uint16_t star_sysret_selector = (X64_USER_CODE_GDT_SEGMENT_OFFSET-16) | 3;
    uint16_t start_syscall_selector = (X64_KERNEL_CODE_GDT_SEGMENT_OFFSET);

    write_msr(X64_MSR_STAR, ((uint64_t)star_sysret_selector << 48)|((uint64_t)start_syscall_selector << 32));
    write_msr(X64_MSR_LSTAR, (uint64_t)(uintptr_t)x64_syscall_entry);
    write_msr(X64_MSR_CSTAR, (uint64_t)(uintptr_t)x64_syscall_entry_compatibility_mode);
    write_msr(X64_MSR_SFMASK, (uint64_t)(X64_RFLAGS_IF_MASK | X64_RFLAGS_RF_MASK | X64_RFLAGS_VM_MASK));

    // Allocate Trampoline Stack
    paddr_t stack_paddr;
    int res = page_alloc(X64_SYSCALL_TRAMPOLINE_STACK_ORDER, &stack_paddr, 0);
    if(res) {
        state->res = res;
        state->done = 1;
        return;
    }
    vaddr_t stack_vaddr = __va(stack_paddr);
    struct x64_syscall_trampoline *trampoline;
    trampoline = percpu_ptr(percpu_addr(x64_local_syscall_trampoline));
    //printk("CPU (%ld) syscall Trampoline %p\n",
    //        (sl_t)current_cpu_id(), trampoline);
    trampoline->trampoline_stack_base
        = (void*)(stack_vaddr + (1ULL << X64_SYSCALL_TRAMPOLINE_STACK_ORDER));
    //printk("CPU (%ld) syscall Trampoline Stack [%p - %p)\n",
    //        (sl_t)current_cpu_id(), stack_vaddr, stack_vaddr + (1ULL << X64_SYSCALL_TRAMPOLINE_STACK_ORDER));

    state->res = 0;
    state->done = 1;
    return;
}

static int
x64_setup_syscalls(void)
{
    int res;
    struct x64_syscall_setup_state state;

    x64_syscall_trampoline_percpu_ptr = (void __percpu *)percpu_addr(x64_local_syscall_trampoline);

    for(cpu_id_t id = 0; id < total_num_cpus(); id++) {
        state.done = 0;
        state.res = 0;
        asm volatile ("mfence" ::: "memory");
        res = xcall_run(id, x64_setup_syscall_xcall, &state);
        if(res) {
            return res;
        }

        while(state.done == 0) {
            asm volatile ("mfence; pause;" ::: "memory");
        }

        res = state.res;
        if(res) {
            return res;
        }
    }

    return 0;
}

declare_init_desc(late, x64_setup_syscalls, "Initializing x64 syscall Instruction");

