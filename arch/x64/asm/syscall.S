
#include <arch/x64/asm/regs.S>

.extern x64_syscall_trampoline_percpu_ptr
.extern x64_route_syscall

.global x64_syscall_entry_compatibility_mode
.type x64_syscall_entry_compatibility_mode, @function

.global x64_syscall_entry
.type x64_syscall_entry, @function

x64_syscall_entry_compatibility_mode: 
    jmp . // This should never happen

x64_syscall_entry:
    // On entry:
    //   %rcx -> user-mode return address
    //   %r11 -> user-mode rflags
    //   %rsp -> unmodified, still pointing into userspace presumably
    //
    //   Interrupts should be disabled

    // We need to swap over to the kernel stack as quickly as possible
    // Preferably without assuming user-mode has a stack set-up at all

    swapgs

    // Store the syscall id into our percpu scratch space
    movq %rax, %gs:8

    // We can then get our current percpu trampoline
    movabsq x64_syscall_trampoline_percpu_ptr, %rax
    addq %gs:0, %rax

    // Stash the user return address
    movq %rcx, 0(%rax)

    // Stash the user stack pointer
    movq %rsp, %rcx
    movq %rcx, 8(%rax)
  
    // Get the percpu trampoline stack pointer
    movq 16(%rax), %rcx
    movq %rcx, %rsp
 
    // we need to preserve all caller saved but %rax and %rcx
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    callq __x64_get_current_thread_kernel_rsp
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdx
    popq %rsi
    popq %rdi

    // Swap to the thread stack
    movq %rax, %rsp

    // Get our percpu offset again
    movabsq x64_syscall_trampoline_percpu_ptr, %rax
    addq %gs:0, %rax

    // Get the user stack pointer and save it on the kernel thread stack
    movq 8(%rax), %rcx
    pushq %rcx

    // Restore %rcx, (the user return address) 
    movq 0(%rax), %rcx

    // Restore %rax (our syscall id) from our scratch space
    movq %gs:8, %rax
  
    // Now we have no dependencies on the trampoline or percpu-scratch space,
    // so interrupts could be safely re-enabled without the chance of another
    // thread running on this CPU corrupting our data

    // Summary:
    //   We've swapped the %gs registers,
    //   Every register other than %rsp is the same as syscall entry
    //   %rsp now points to our kernel thread stack, and we pushed the user
    //   stack pointer onto our thread stack.

    PUSH_CALLER_REGS();
    PUSH_CALLEE_REGS();

    // Get a pointer to our registers on the stack
    movq %rsp, %rdi

    // Stack Alignment
    andq $(~0xF), %rsp
    pushq %rdi

    // Actually deal with routing the syscall
    callq x64_route_syscall

    // Undo stack alignment
    popq %rdi
    movq %rdi, %rsp

    POP_CALLEE_REGS();
    POP_CALLER_REGS();

    // Pop the user stack
    popq %rdi
    movq %rdi, %rsp

    // Restore the Usermode %gs Selector
    swapgs
    
    // Set Usermode CS and SS, jump to %rcx and restore %r11 rflags
    sysretq

