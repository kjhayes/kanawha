
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif

#include <arch/x64/asm/regs.S>
#include <arch/x64/asm/iret.S>
#include <arch/x64/exception.h>
#include <kanawha/xmacro.h>

#define EXCP_ENTRY_ORDER 4
#define EXCP_ENTRY_SIZE (1<<EXCP_ENTRY_ORDER)

#define IRET_SAVE_SIZE 0x28

.extern __x64_get_current_thread_kernel_rsp

.global x64_exception_entry_ring_change_entry
.type x64_exception_entry_ring_change_entry, @function
.global x64_exception_entry_ring_change_exit
.type x64_exception_entry_ring_change_exit, @function

.global x64_exception_entry_size
x64_exception_entry_size:
.quad EXCP_ENTRY_SIZE
.global x64_interrupt_entry_size
x64_interrupt_entry_size:
.quad EXCP_ENTRY_SIZE

#define X64_DECLARE_EXCP_ENTRY(VECTOR, MNEMONIC, DESC, HAS_ERRCODE, TYPE, ...)\
.type __x64_exception_ ## VECTOR ## _entry, @function;\
__x64_exception_ ## VECTOR ## _entry:;\
.if HAS_ERRCODE;\
.else;\
pushq $0;\
.endif;\
pushq $(VECTOR);\
jmp x64_exception_entry_common;\
.p2align EXCP_ENTRY_ORDER, 0xcc;

//__x64_exception_ ## VECTOR ## _entry_end:

.global x64_exception_entry_table
x64_exception_entry_table:
.p2align EXCP_ENTRY_ORDER, 0xcc;\
X64_EXCP_XLIST(X64_DECLARE_EXCP_ENTRY)

// Fake more "INTR" type exception handlers
#define X64_DECLARE_IRQ_ENTRY(VECTOR, ...) X64_DECLARE_EXCP_ENTRY(VECTOR, INTR, "Interrupt", 0, X64_EXCP_TYPE_INTR)
.global x64_interrupt_entry_table
x64_interrupt_entry_table:
.p2align EXCP_ENTRY_ORDER, 0xcc;\
XRANGE_32_63(X64_DECLARE_IRQ_ENTRY)
XRANGE_64_127(X64_DECLARE_IRQ_ENTRY)
XRANGE_128_255(X64_DECLARE_IRQ_ENTRY)

.extern x64_handle_exception
.type x64_exception_entry_common, @function
x64_exception_entry_common:

  PUSH_CALLER_REGS();

  // Get a pointer to our state on the stack
  movq %rsp, %rdx

  // Get our return CS descriptor
  movq (CALLER_PUSH_SIZE + 16 + 8)(%rsp), %rax
  testq $3, %rax // Test the ring we came from
  jz no_ring_change_entry

x64_exception_entry_ring_change_entry:
  // We are coming from ring 3 (technically could be 1 or 2 also)

  // Swap back to the kernel %gs so we can access percpu variables
  swapgs

  // Get our thread stack
  callq __x64_get_current_thread_kernel_rsp

  movq $(CALLER_PUSH_SIZE + 16 + IRET_SAVE_SIZE), %rcx // Length (iret structure, error code, vector, and caller regs)
  subq %rcx, %rax // Allocate space on the kernel stack
  movq %rax, %rsp // Transfer over to the kernel thread stack

  movq %rax, %rdi // Destination (Thread Stack)
  movq %rdx, %rsi // Source (Transition Stack)
 
  // Perform the "memcpy"
  rep movsb
  
no_ring_change_entry:
  // Here we should be running without our correct thread stack

  // Stack alignment trickery
  andq $(~0xF), %rsp
  pushq %rdx

  movq %rdx, %rdi
  callq x64_handle_exception

  // Undoing stack alignment trickery
  popq %rdx
  movq %rdx, %rsp

  // Check if we came from an outer ring
  movq (CALLER_PUSH_SIZE + 16 + 8)(%rsp), %rax
  testq $3, %rax
  jz no_ring_change_exit

x64_exception_entry_ring_change_exit:
  // We need to restore the user-mode %gs register
  swapgs

no_ring_change_exit:
  POP_CALLER_REGS();

  // Pop the Error Code and the Vector
  addq $16, %rsp

  iretq

// C Wrapper Function to do nop iret
.global x64_nop_iret
.type x64_nop_iret, @function
x64_nop_iret:
  NOP_IRET_STUB
  retq

