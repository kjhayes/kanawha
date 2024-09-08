
#include <arch/x64/asm/regs.S>

.extern thread_switch
.extern query_resched

// On entry:
//   Stack is misaligned by 8 bytes
//   Top of stack is the function pointer of our thread
//   %rdi -> our "in" void* argument 

.global __x64_thread_entry
.type __x64_thread_entry, @function
__x64_thread_entry:
    movq 0(%rsp), %rax // Get our function

    callq *%rax // Call our function (%rdi is already set correctly)
                // (Also aligns the stack)

    callq force_resched 
    movq %rax, %rdi // If this is NULL we will run the idle thread

    callq thread_abandon // Aligns the stack
    // This should never happen...
    // Stack is misaligned

__x64_returned_from_thread_abandon:
    jmp __x64_returned_from_thread_abandon

.global __x64_thread_run_threadless
.type __x64_thread_run_threadless, @function

__x64_thread_run_threadless: 
    // Save our flags and disable interrupts
    pushfq
    cli 
    // Save all registers (this isn't strictly necessary but we'll be safe for now)
    PUSH_CALLER_REGS()
    PUSH_CALLEE_REGS()

    // Save our stack
__x64_thread_stack_save:
    movq %rsp, 0(%rdx)

    // We are now effectively "threadless"

    // Align the stack
    movq %rsp, %rdx
    andq $(~0xF), %rsp
    pushq %rdx
   
    // %rdi already has our "in" argument
    callq *%rsi

    // Undo stack alignment
    popq %rdx
    movq %rdx, %rsp

    // the threadless_f* we just called should be noreturn,
    // so we never reach this loop.
    jmp .


.global __x64_thread_run_thread
.type __x64_thread_run_thread, @function

__x64_thread_run_thread:

    // Restore our stack
__x64_thread_stack_restore:
    movq %rdi, %rsp

    // Restore our registers
    POP_CALLEE_REGS()
    POP_CALLER_REGS()

    // Restore RFLAGS
    popfq

    // Return to our thread
    retq


.global __x64_enter_usermode
.type __x64_enter_usermode, @function
__x64_enter_usermode:

    // Don't allow interrupts during this process
    cli

    // Protect the kernel mode %gs_base
    swapgs
   
    subq $0x40, %rsp // Allocate room for our fake iret structure

    movq %rdi, 0(%rsp) // Place our usermode RIP into the structure

    // Set the rest of the structure to zero on the stack
    movq %rsp, %rdi
    addq $8, %rdi
    xorq %rax, %rax
    movq $((0x40 - 8)/8), %rcx
    rep stosq

    movw $0x2B, %ax // Usermode Data GDT Selector
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    movw %ax, 32(%rsp) // SS on the stack

    movw $0x33, %ax // Usermode Code GDT Selector
    movw %ax, 8(%rsp) // CS on the stack

    // Set our intial RFLAGS
    pushf
    popq %rax
    orq $(1<<9), %rax // Enable Interrupts in User-Mode
    movq %rax, 16(%rsp) // RFLAGS on the stack

    // Leave our return %rsp as zero

    // Place the "arg" into the first kernel syscall
    // argument register
    movq %rsi, %rdi

    // Zero out the rest of our GPRs
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %rsi, %rsi
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15

    iretq

