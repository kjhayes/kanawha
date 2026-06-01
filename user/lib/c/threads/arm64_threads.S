
#define STACK_SIZE 0x10000

.align 4
.globl _thrd_start
.type _thrd_start,@function
_thrd_start:
  mov x20, x0 // Thread Creation State

  // Map the Stack
  mov x0, 0
  mov x1, 0
  // Pointer to stash the new stack location
  add x2, x20, 16
  mov x3, STACK_SIZE
  mov x4, (0b10 | (1<<3) | (1<<4))
  mov x8, 7
  svc 0
  cbnz x0, __do_fail_exit

  // Start using our new stack
  ldr x0, [x20, 16]
  mov x1, STACK_SIZE
  add x0, x0, x1
  mov sp, x0

  ldr x0,  [x20, 8]
  ldr x21, [x20, 0]

  // Mark us as inited (x20 now invalid)
  mov x1, 1
  str x1, [x20, 24]

  blr x21

  // Exit
  mov x8, 0
  svc 0
  b .


__do_fail_exit:
  mov x8, 0
  svc 0
  b .

