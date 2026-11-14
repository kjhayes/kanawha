
.section .text, "ax"

.code64
.global __x64_cpuid_supported
.type __x64_cpuid_supported, @function
__x64_cpuid_supported:
    // Outermost EFLAGS Save
    pushfq
    
    // Try changing the ID bit
    pushfq
    xorq $(1<<21), 0(%rsp)
    popfq
    
    // Get the (hopefully changed) EFLAGS value
    pushfq
    popq %rax
    
    // XOR with the original EFLAGS value on the stack
    xorq 0(%rsp), %rax
    
    // Outermost EFLAGS Restore
    popfq
    
    // %eax will be zero if CPUID isn't supported, else non-zero
    retq


// rdi -> uint32_t eax
// rsi -> uint32_t ecx
// rdx -> struct x64_cpuid * ( packed uint32_t eax, ebx, ecx, edx )
.global __x64_cpuid_ext
.type __x64_cpuid_ext, @function
__x64_cpuid_ext:

    pushq %rbx
    pushq %r8

    movq %rdx, %r8

    movl %edi, %eax
    movl %esi, %ecx

    cpuid
    
    movl %eax, 0(%r8)
    movl %ebx, 4(%r8)
    movl %ecx, 8(%r8)
    movl %edx, 12(%r8)
    
    popq %r8
    popq %rbx
    
    retq

