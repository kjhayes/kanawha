
#include <arch/arm64/asm/regs.h>

.global __arm64_thread_entry
.type __arm64_thread_entry, @function
__arm64_thread_entry:
    // x0 -> void *in
    // x1 -> void(*func)(void *in)
    br x1

.global __arm64_thread_run_threadless
.type __arm64_thread_run_threadless, @function
__arm64_thread_run_threadless:
    // x0 -> void *in
    // x1 -> void(*func)(void *in)
    // x2 -> void **sp_save_ptr
    PUSH_CALLER_REGS()
    PUSH_CALLEE_REGS()

    // Save the stack
    mov x0, sp
    str x0, [x2, 0x0]

    br x1
   
    // Should never get here
    b .

.global __arm64_thread_run_thread
.type __arm64_thread_run_thread, @function
__arm64_thread_run_thread:
    // x0 -> stack pointer
    mov sp, x0
    POP_CALLEE_REGS()
    POP_CALLER_REGS()
    ret
