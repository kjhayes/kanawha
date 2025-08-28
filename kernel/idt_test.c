
#include <kanawha/init.h>
#include <arch/x64/idt.h>
#include <arch/x64/gdt.h>
#include <arch/x64/exception.h>

static int
mess_with_the_idt(void) {

    void __user *entry_addr = (void __user *)0x00000000004008d0; // trap_entry

    struct idt64_entry *desc = &x64_idt64.exception_descriptors[3];

    desc->offset_0_15 = ((uintptr_t)entry_addr) & 0xFFFF;
    desc->offset_16_31 = (((uintptr_t)entry_addr) >> 16) & 0xFFFF;
    desc->offset_32_64 = (((uintptr_t)entry_addr) >> 32) & 0xFFFFFFFF;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_DPL_MASK)
        | IDT64_ENTRY_FLAG_DPL_RING3;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_IST_MASK)
        | IDT64_ENTRY_FLAG_IST_NONE;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_GATE_TYPE_MASK)
        | IDT64_ENTRY_FLAG_GATE_TYPE_INTERRUPT; // We still want IF disabled on user exceptions, so we
                                                // don't have a race condition setting swapgs

    desc->flags |= IDT64_ENTRY_FLAG_PRESENT;

    desc->segment_selector = x64_segment_selector(X64_USER_CODE_GDT_SEGMENT_OFFSET,0,0);

    // Reload the IDT just to be safe
    x64_load_idt(&x64_idt64);

    return 0;
}
//declare_init_desc(launch, mess_with_the_idt, "Messing with the IDT");

