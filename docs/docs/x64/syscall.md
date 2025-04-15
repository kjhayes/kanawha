
Kanawha Kernel x64 Syscall Calling Convention
=============================================

Place the syscall ID into `%rax`

Argument Register Order

1. `%rdi`
2. `%rsi`
3. `%rdx`
4. `%r8`
5. `%r9`
6. `%r10`

Invoke `syscall` Instruction

Return Value (if one exists) -> `%rax`

Caller Saved Registers:
  `%rax`, `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9`, `%r10`, `%r11`

Callee Saved Registers:
  `%rbx`, `%rbp`, `%r12`, `%r13`, `%r14`, `%r15`, `%rsp`

