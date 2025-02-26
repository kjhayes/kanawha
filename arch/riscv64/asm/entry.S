
.section .boot.text

.global riscv64_kernel_entry
.type riscv64_kernel_entry, @function

riscv64_kernel_entry:
    j riscv64_kernel_entry

