#ifndef __KANAWHA__X64_MULTIBOOT2_ENTRY_S__
#define __KANAWHA__X64_MULTIBOOT2_ENTRY_S__

.extern x64_prot_to_long_mode
.extern boot_mb2_info_ptr
.extern mb2_info_ptr

.section .boot.text, "ax"

.code32
.global x64_multiboot2_entry
.type x64_multiboot2_entry, @function
x64_multiboot2_entry: 

  // Check the magic number
  movl $0x36d76289, %esi
  cmpl %esi, %eax
  jnz x64_multiboot2_entry__invalid_magic 

  // Save the Multiboot2 Data pointer given to us in %ebx
  movl $boot_mb2_info_ptr, %esi
  movl %ebx, 0(%esi)

  mov $x64_multiboot2_entry_long_mode, %edi
  mov $0, %esi

  mov $1, %edx

  jmp x64_prot_to_long_mode

.code32
x64_multiboot2_entry__invalid_magic:
  // TODO: Attempt to log an error
  jmp .

.code64
x64_multiboot2_entry_long_mode:
  // We made it to 64-bit code!
  jmp x64_common_entry

#endif
