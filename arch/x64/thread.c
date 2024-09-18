
#include <arch/x64/asm/regs.S>
#include <arch/x64/stack.h>
#include <kanawha/thread.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>
#include <kanawha/percpu.h>
#include <kanawha/assert.h>

extern void __x64_thread_entry(void);

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
            &current_thread()->arch_state.stack.rsp);
}

__attribute__((noreturn)) void
arch_thread_run_thread(struct thread_state *to_run)
{
    dprintk("running thread %p with rsp=%p\n",
            to_run, to_run->arch_state.stack.rsp);
    __x64_thread_run_thread((void*)to_run->arch_state.stack.rsp);
}

#define thread_alloca(_STACK_STATE_PTR, _AMT)\
  ({\
   void *val;\
   (_STACK_STATE_PTR)->rsp -= (uint64_t)(_AMT);\
   val = (void*)((_STACK_STATE_PTR)->rsp);\
   val;\
   })

#define thread_push(_STACK_STATE_PTR, _VALUE)\
  do {\
    (_STACK_STATE_PTR)->rsp -= sizeof(_VALUE);\
    *((typeof(_VALUE)*)(_STACK_STATE_PTR)->rsp) = (_VALUE);\
  } while(0)

// 64kb Stacks
#define KERNEL_THREAD_STACK_ORDER 16

int
arch_init_thread_state(struct thread_state *state)
{
    int res;

    struct arch_thread_state *arch = &state->arch_state;
    struct x64_thread_stack *stack = &state->arch_state.stack;

    res = x64_thread_stack_init(state, KERNEL_THREAD_STACK_ORDER);
    if(res) {
        return res;
    }

    dprintk("state->func = %p\n", state->func);
    dprintk("__x64_thread_entry = %p\n", __x64_thread_entry);

    thread_push(stack, (uint64_t)state->func);
    thread_push(stack, (uint64_t)__x64_thread_entry);

    uint64_t initial_rflags = 0x0;
    thread_push(stack, (uint64_t)initial_rflags);

    void *regs = thread_alloca(stack, (CALLEE_PUSH_SIZE + CALLER_PUSH_SIZE));
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
    int res;
    struct arch_thread_state *arch = &state->arch_state;
    res = x64_thread_stack_deinit(state);
    if(res) {
        return res;
    }
    return 0;
}

int
arch_dump_thread(printk_f *printer, struct thread_state *state)
{
    struct arch_thread_state *arch_state = &state->arch_state;
    struct x64_thread_stack *stack = &arch_state->stack;
    void *kernel_stack_base = (void*)stack->stack_top + (1ULL<<stack->order);
    size_t allocated = (uintptr_t)kernel_stack_base - (uintptr_t)stack->rsp;
    (*printer)("Kernel Stack Size      : 0x%llx\n", (unsigned long long)(1ULL<<stack->order));
    (*printer)("Kernel Stack Allocated : 0x%llx\n", (unsigned long long)allocated);
    (*printer)("Kernel Stack Base      : 0x%llx\n", (unsigned long long)kernel_stack_base);
    (*printer)("Kernel Stack Pointer   : 0x%llx\n", (unsigned long long)stack->rsp);
    (*printer)("Kernel Stack Top       : 0x%llx\n", (unsigned long long)stack->stack_top);
    (*printer)("--- Kernel Stack ---\n");

    size_t num_64 = allocated / sizeof(uint64_t);
    size_t extra_bytes = allocated % sizeof(uint64_t);
    for(ssize_t i = num_64-1; i >= 0; i--) {
        (*printer)("[uint64_t] %p : 0x%llx\n",
                &((uint64_t*)(stack->rsp + extra_bytes))[i],
                ((uint64_t*)(stack->rsp + extra_bytes))[i]);
    }
    for(ssize_t i = extra_bytes - 1; i >= 0; i++) {
        (*printer)("[uint8_t] %p : 0x%x\n",
                &((uint8_t*)stack->rsp)[i],
                ((uint8_t*)stack->rsp)[i]);
    }

    (*printer)("-------------------\n");
    return 0;
}

// This is just to avoid hard-coding any struct offsets into assembly
void *__x64_get_current_thread_kernel_rsp(void)
{
    DEBUG_ASSERT_PERCPU_VALID();
    struct thread_state *thread = current_thread();
    return (void*)(uintptr_t)thread->arch_state.stack.rsp;
}


