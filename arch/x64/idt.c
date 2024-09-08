
#include <arch/x64/idt.h>

#include <kanawha/printk.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>
#include <kanawha/stdint.h>
#include <arch/x64/gdt.h>

extern size_t x64_exception_entry_size;
extern size_t x64_interrupt_entry_size;
extern int x64_exception_entry_table[];
extern int x64_interrupt_entry_table[];

struct idt64 x64_idt64;

void
x64_setup_idt_exception_descriptor(
        struct idt64_entry *desc,
        void *excp_entry)
{
    memset(desc, 0, sizeof(struct idt64_entry));
    desc->offset_0_15 = ((uintptr_t)excp_entry) & 0xFFFF;
    desc->offset_16_31 = (((uintptr_t)excp_entry) >> 16) & 0xFFFF;
    desc->offset_32_64 = (((uintptr_t)excp_entry) >> 32) & 0xFFFFFFFF;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_DPL_MASK)
        | IDT64_ENTRY_FLAG_DPL_RING0;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_IST_MASK)
        | IDT64_ENTRY_FLAG_IST_NONE;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_GATE_TYPE_MASK)
        | IDT64_ENTRY_FLAG_GATE_TYPE_INTERRUPT; // We still want IF disabled on user exceptions, so we
                                                // don't have a race condition setting swapgs

    desc->flags |= IDT64_ENTRY_FLAG_PRESENT;

    desc->segment_selector = x64_segment_selector(X64_KERNEL_CODE_GDT_SEGMENT_OFFSET,0,0);
}

void
x64_setup_idt_interrupt_descriptor(
        struct idt64_entry *desc,
        void *irq_entry)
{
    memset(desc, 0, sizeof(struct idt64_entry));
    desc->offset_0_15 = ((uintptr_t)irq_entry) & 0xFFFF;
    desc->offset_16_31 = (((uintptr_t)irq_entry) >> 16) & 0xFFFF;
    desc->offset_32_64 = (((uintptr_t)irq_entry) >> 32) & 0xFFFFFFFF;


    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_DPL_MASK)
        | IDT64_ENTRY_FLAG_DPL_RING0;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_IST_MASK)
        | IDT64_ENTRY_FLAG_IST_NONE;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_GATE_TYPE_MASK)
        | IDT64_ENTRY_FLAG_GATE_TYPE_INTERRUPT;

    desc->flags |= IDT64_ENTRY_FLAG_PRESENT;

    desc->segment_selector = x64_segment_selector(X64_KERNEL_CODE_GDT_SEGMENT_OFFSET,0,0);
}

void
x64_setup_idt(
        struct idt64 *idt,
        void *excp_entry_table,
        size_t excp_entry_size,
        void *irq_entry_table,
        size_t irq_entry_size)
{
    for(int i = 0; i < 32; i++) {
        x64_setup_idt_exception_descriptor(
                &idt->exception_descriptors[i],
                excp_entry_table + (i * excp_entry_size));
    }
    for(int i = 0; i < (256-32); i++) {
        x64_setup_idt_interrupt_descriptor(
                &idt->interrupt_descriptors[i],
                irq_entry_table + (i * irq_entry_size));
    }
}

void
x64_load_idt(struct idt64 *idt) {
    struct idt64_descriptor idtr;
    idtr.offset = (uint64_t)idt;
    idtr.size = sizeof(struct idt64);
    asm volatile ("lidtq (%0)" :: "r" (&idtr) : "memory");
}

void
x64_init_idt_bsp(void) {
    x64_setup_idt(
            &x64_idt64,
            x64_exception_entry_table,
            x64_exception_entry_size,
            x64_interrupt_entry_table,
            x64_interrupt_entry_size);

    x64_load_idt(&x64_idt64);
}

void
x64_init_idt_ap(void) {
    x64_load_idt(&x64_idt64);
}

