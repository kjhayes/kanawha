
#include <kanawha/excp.h>
#include <kanawha/init.h>
#include <kanawha/usermode.h>
#include <kanawha/percpu.h>
#include <kanawha/vmem.h>
#include <kanawha/page_alloc.h>
#include <kanawha/syscall.h>
#include <kanawha/xcall.h>
#include <kanawha/process.h>
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
    syscall_id_t id = state->caller_regs[PUSHED_CALLER_REGS_INDEX_RAX];
    void __user *user_return = (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RCX];
    uint64_t user_rflags = state->caller_regs[PUSHED_CALLER_REGS_INDEX_R11];

    uint64_t *ret_val = &state->caller_regs[PUSHED_CALLER_REGS_INDEX_RAX];

    dprintk("x64_route_syscall (id=%ld, user_return=0x%llx, user_rflags=0x%llx)\n",
            (sl_t)id, user_return, (uintptr_t)user_rflags);

    struct x64_syscall_trampoline *tramp = 
            percpu_ptr(percpu_addr(x64_local_syscall_trampoline));
    dprintk("TRAMPOLINE (user_stack=%p) (user_rip=%p) (trampoline_stack=%p)\n",
            tramp->user_stack,
            tramp->user_return,
            tramp->trampoline_stack_base);

    struct process *process = current_process();

    switch(id) {
        case SYSCALL_ID_EXIT:
            syscall_exit(process, state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI]);
            break;
        case SYSCALL_ID_OPEN:
            *ret_val = (uint64_t)(fd_t)
                syscall_open(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // parent
                        (const char __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // name
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // path_length
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8], // perm
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R9] // mode
                        );
            break;
        case SYSCALL_ID_CLOSE:
            *ret_val = (int)
                syscall_close(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI]);
            break;
        case SYSCALL_ID_READ:
            *ret_val = (uint64_t)(int)
                syscall_read(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // dst
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // src_offset
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8] // size
                        );
            break;
        case SYSCALL_ID_WRITE:
            *ret_val = (uint64_t)(int)
                syscall_write(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // dst_offset
                        (void __user *)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // src
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8] // size
                        );
            break;
        case SYSCALL_ID_MMAP:
            *ret_val = (uint64_t)(int)
                syscall_mmap(
                        process,
                        (fd_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDI], // file
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RSI], // file offset
                        (void __user **)state->caller_regs[PUSHED_CALLER_REGS_INDEX_RDX], // where
                        (size_t)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R8], // size
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R9], // access_flags
                        (unsigned long)state->caller_regs[PUSHED_CALLER_REGS_INDEX_R10] // mmap_flags
                        );
        default:
            syscall_unknown(process, id);
    }
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
