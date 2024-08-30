
.section .text, "ax"

.code64
.global x64_cpuid_supported
.type x64_cpuid_supported, @function
x64_cpuid_supported:

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
// rsi -> struct x64_cpuid_result * ( packed uint32_t eax, ebx, ecx, edx )
.global x64_cpuid
.type x64_cpuid, @function
x64_cpuid:

pushq %rbx
// Misaligned stack but we should be fine because we leave it alone until popq %rbx

movl %edi, %eax
cpuid

movl %eax, 0(%rsi)
movl %ebx, 4(%rsi)
movl %ecx, 8(%rsi)
movl %edx, 12(%rsi)

popq %rbx

retq

