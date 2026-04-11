
.section .boot.text, "ax"

.global arm64_kernel_entry
.type arm64_kernel_entry, @function
arm64_kernel_entry:
    b .

