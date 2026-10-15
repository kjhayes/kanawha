
#include <arch/x64/idt.h>

#include <arch/x64/cpu.h>
#include <arch/x64/gdt.h>
#include <kanawha/printk.h>
#include <kanawha/string.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <arch/x64/segdesc.h>
#include <kanawha/attribute.h>
#include <kanawha/types.h>
#include <kanawha/xcall.h>

struct __packed idt64
{
    struct idt64_entry exception_descriptors[32];
    struct idt64_entry interrupt_descriptors[256 - 32];
};

_Static_assert(sizeof(struct idt64) == (sizeof(struct idt64_entry) * 256),
               "IDT64 is not the same size as 256 IDT64 entries!");

struct __packed idt64_descriptor
{
    uint16_t size;
    uint64_t offset;
};

struct x64_idt
{
    ilist_t cpu_list;
    union {
        struct idt64 idt64;
    };
};

struct x64_idt default_x64_idt = {
    DECLARE_FIELD_ILIST(default_x64_idt, cpu_list),
    .idt64 = {0},
};

static void
x64_setup_idt_exception_descriptor(struct idt64_entry *desc, void *excp_entry)
{
    memset(desc, 0, sizeof(struct idt64_entry));
    desc->offset_0_15 = ((uintptr_t)excp_entry) & 0xFFFF;
    desc->offset_16_31 = (((uintptr_t)excp_entry) >> 16) & 0xFFFF;
    desc->offset_32_64 = (((uintptr_t)excp_entry) >> 32) & 0xFFFFFFFF;

    desc->flags &= ~IDT64_ENTRY_FLAG_DPL_MASK;
    desc->flags |= IDT64_ENTRY_FLAG_DPL_RING0;

    desc->flags &= ~IDT64_ENTRY_FLAG_IST_MASK;
    desc->flags |= IDT64_ENTRY_FLAG_IST_NONE;

    // We still want IF disabled on user exceptions, so we
    // don't have a race condition setting swapgs
    desc->flags &= ~IDT64_ENTRY_FLAG_GATE_TYPE_MASK;
    desc->flags |= IDT64_ENTRY_FLAG_GATE_TYPE_INTERRUPT;

    desc->flags |= IDT64_ENTRY_FLAG_PRESENT;

    desc->segment_selector =
        x64_segment_selector(X64_KERNEL_CODE_GDT_SEGMENT_OFFSET, 0, 0);
}

static void
x64_setup_idt_interrupt_descriptor(struct idt64_entry *desc, void *irq_entry)
{
    memset(desc, 0, sizeof(struct idt64_entry));
    desc->offset_0_15 = ((uintptr_t)irq_entry) & 0xFFFF;
    desc->offset_16_31 = (((uintptr_t)irq_entry) >> 16) & 0xFFFF;
    desc->offset_32_64 = (((uintptr_t)irq_entry) >> 32) & 0xFFFFFFFF;

    desc->flags =
        (desc->flags & ~IDT64_ENTRY_FLAG_DPL_MASK) | IDT64_ENTRY_FLAG_DPL_RING0;

    desc->flags =
        (desc->flags & ~IDT64_ENTRY_FLAG_IST_MASK) | IDT64_ENTRY_FLAG_IST_NONE;

    desc->flags = (desc->flags & ~IDT64_ENTRY_FLAG_GATE_TYPE_MASK) |
                  IDT64_ENTRY_FLAG_GATE_TYPE_INTERRUPT;

    desc->flags |= IDT64_ENTRY_FLAG_PRESENT;

    desc->segment_selector =
        x64_segment_selector(X64_KERNEL_CODE_GDT_SEGMENT_OFFSET, 0, 0);
}

static void
x64_setup_idt64(struct idt64 *idt,
              void *excp_entry_table,
              size_t excp_entry_size,
              void *irq_entry_table,
              size_t irq_entry_size)
{
    for(int i = 0; i < 32; i++)
    {
        x64_setup_idt_exception_descriptor(&idt->exception_descriptors[i],
                                           excp_entry_table +
                                           (i * excp_entry_size));
    }
    for(int i = 0; i < (256 - 32); i++)
    {
        x64_setup_idt_interrupt_descriptor(&idt->interrupt_descriptors[i],
                                           irq_entry_table +
                                           (i * irq_entry_size));
    }
}

static void
x64_setup_idt64_kernel_entries(
        struct idt64 *idt)
{
extern size_t x64_exception_entry_size;
extern size_t x64_interrupt_entry_size;
extern int x64_exception_entry_table[];
extern int x64_interrupt_entry_table[];

    x64_setup_idt64(idt,
                  x64_exception_entry_table,
                  x64_exception_entry_size,
                  x64_interrupt_entry_table,
                  x64_interrupt_entry_size);
}

static void
x64_load_idt64(struct idt64 *idt)
{
    struct idt64_descriptor idtr;
    idtr.offset = (uint64_t)idt;
    idtr.size = sizeof(struct idt64);
    asm volatile("lidtq (%0)" ::"r"(&idtr) : "memory");
}

void
x64_init_default_idt_bsp(void)
{
    x64_setup_idt64_kernel_entries(&default_x64_idt.idt64);
    x64_load_idt64(&default_x64_idt.idt64);
}

void
x64_init_default_idt_ap(void)
{
    x64_load_idt64(&default_x64_idt.idt64);
}

struct x64_idt *
x64_get_default_idt(void)
{
    return &default_x64_idt;
}

static void
x64_reload_idt_xcall(void *_ign)
{
    struct cpu *gen_cpu = current_cpu();
    struct x64_cpu *cpu = container_of(gen_cpu, struct x64_cpu, cpu);

    struct x64_idt *idt = cpu->idt;
    if(idt != NULL) {
        x64_load_idt64(&idt->idt64);
    }
}

int
x64_cpu_set_idt(
        struct x64_idt *idt,
        struct x64_cpu *cpu)
{
    if(cpu->idt == NULL) {
        cpu->idt = idt;
        ilist_push_tail(&idt->cpu_list, &cpu->idt_node);
    } else {
        ilist_remove(&cpu->idt->cpu_list, &cpu->idt_node);
        cpu->idt = idt;
        ilist_push_tail(&idt->cpu_list, &cpu->idt_node);
    }

    if(completed_init_stage_xcall()) {
        if(completed_init_stage_smp()) {
            // We are fully up and running and can wait for this
            // xcall to complete
            xcall_run(cpu->cpu.id, x64_reload_idt_xcall, NULL);
        } else {
            // We can only queue the xcall to run whenever this
            // CPU next checks its X-Call queue.
            xcall_queue(cpu->cpu.id, x64_reload_idt_xcall, NULL);
        }
    }

    return 0;
}

static int
x64_reload_all_smp_idt(void)
{
    int res;
    res = xcall_broadcast(x64_reload_idt_xcall, NULL);
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(smp, x64_reload_all_smp_idt, "Reloading All CPU IDT(s)");

