
RISCV64 Syscalls
================

Calling Convention
------------------

A syscall is invoked using the ``ecall`` instruction in u-mode.

The syscall id is placed into ``a7`` and up to 6 arguments are passed in sequential order from ``a0`` to ``a5``

``sp`` and ``s0`` to ``s11`` should be preserved by the kernel.
The argument registers ``a0`` to ``a7`` and the temporary registers ``t0`` to ``t6`` must be preserved by the caller.

