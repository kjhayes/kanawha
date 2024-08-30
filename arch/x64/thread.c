
#include <arch/x64/asm/regs.S>
#include <kanawha/thread.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>
#include <kanawha/percpu.h>

extern void __x64_thread_entry(void);

__attribute__((noreturn))
extern void *
__x64_thread_run_threadless(void *in, threadless_f *func, uint64_t *rsp_ptr);

extern __attribute__((noreturn)) void
__x64_thread_run_thread(void *rsp);

void 
arch_thread_run_threadless(
        threadless_f *func,
        void *in)
{
    __x64_thread_run_threadless(
            in, func,
            &current_thread()->arch_state.kernel_rsp);
}

__attribute__((noreturn)) void
arch_thread_run_thread(struct thread_state *to_run)
{
    __x64_thread_run_thread((void*)to_run->arch_state.kernel_rsp);
}

#define thread_alloca(_ARCH_STATE_PTR, _AMT)\
  ({\
   void *val;\
   (_ARCH_STATE_PTR)->kernel_rsp -= (uint64_t)(_AMT);\
   val = (void*)((_ARCH_STATE_PTR)->kernel_rsp);\
   val;\
   })

#define thread_push(_ARCH_STATE_PTR, _VALUE)\
  do {\
    (_ARCH_STATE_PTR)->kernel_rsp -= sizeof(_VALUE);\
    *((typeof(_VALUE)*)(_ARCH_STATE_PTR)->kernel_rsp) = (_VALUE);\
  } while(0)

// 16kb Stacks
#define KERNEL_THREAD_STACK_SIZE 0x4000

int
arch_init_thread_state(struct thread_state *state)
{
    struct arch_thread_state *arch = &state->arch_state;

    arch->kernel_stack_size = KERNEL_THREAD_STACK_SIZE;
    arch->kernel_stack_top = kmalloc(arch->kernel_stack_size);
    if(arch->kernel_stack_top == NULL) {
        return -ENOMEM;
    }
    arch->kernel_rsp = (uint64_t)(arch->kernel_stack_top + arch->kernel_stack_size);

    dprintk("state->func = %p\n", state->func);
    dprintk("__x64_thread_entry = %p\n", __x64_thread_entry);
    thread_push(arch, (uint64_t)state->func);
    thread_push(arch, (uint64_t)__x64_thread_entry);

    void *regs = thread_alloca(arch, (CALLEE_PUSH_SIZE + CALLER_PUSH_SIZE));
    memset(regs, 0, CALLEE_PUSH_SIZE + CALLER_PUSH_SIZE);

    uint64_t *callee_regs = regs;
    uint64_t *caller_regs = regs + CALLEE_PUSH_SIZE;

    caller_regs[1] = (uint64_t)state->in; //rdi

    //arch_dump_thread(printk, state);

    return 0;
}

int
arch_deinit_thread_state(struct thread_state *state)
{
    struct arch_thread_state *arch = &state->arch_state;
    kfree(arch->kernel_stack_top);
    return 0;
}

int
arch_dump_thread(printk_f *printer, struct thread_state *state)
{
    struct arch_thread_state *arch_state = &state->arch_state;
    void *kernel_stack_base = arch_state->kernel_stack_top + arch_state->kernel_stack_size;
    size_t allocated = (uintptr_t)kernel_stack_base - (uintptr_t)arch_state->kernel_rsp;
    (*printer)("Kernel Stack Size      : 0x%llx\n", (unsigned long long)arch_state->kernel_stack_size);
    (*printer)("Kernel Stack Allocated : 0x%llx\n", (unsigned long long)allocated);
    (*printer)("Kernel Stack Base      : 0x%llx\n", (unsigned long long)kernel_stack_base);
    (*printer)("Kernel Stack Pointer   : 0x%llx\n", (unsigned long long)arch_state->kernel_rsp);
    (*printer)("Kernel Stack Top       : 0x%llx\n", (unsigned long long)arch_state->kernel_stack_top);
    (*printer)("--- Kernel Stack ---\n");

    size_t num_64 = allocated / sizeof(uint64_t);
    size_t extra_bytes = allocated % sizeof(uint64_t);
    for(ssize_t i = num_64-1; i >= 0; i--) {
        (*printer)("[uint64_t] %p : 0x%llx\n",
                &((uint64_t*)(arch_state->kernel_rsp + extra_bytes))[i],
                ((uint64_t*)(arch_state->kernel_rsp + extra_bytes))[i]);
    }
    for(ssize_t i = extra_bytes - 1; i >= 0; i++) {
        (*printer)("[uint8_t] %p : 0x%x\n",
                &((uint8_t*)arch_state->kernel_rsp)[i],
                ((uint8_t*)arch_state->kernel_rsp)[i]);
    }

    (*printer)("-------------------\n");
    return 0;
}

// This is just to avoid hard-coding any struct offsets into assembly
__attribute__((no_caller_saved_registers))
void *__x64_get_current_thread_kernel_rsp(void)
{
    return (void*)(uintptr_t)current_thread()->arch_state.kernel_rsp;
}


