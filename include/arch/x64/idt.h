#ifndef __KANAWHA__IDT_H__
#define __KANAWHA__IDT_H__

#include <arch/x64/segdesc.h>
#include <kanawha/attribute.h>
#include <kanawha/types.h>

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

extern struct idt64 x64_idt64;

void
x64_setup_idt_exception_entry(struct idt64_entry *desc, void *excp_entry);
void
x64_setup_idt_interrupt_entry(struct idt64_entry *desc, void *irq_entry);

void
x64_setup_idt(struct idt64 *idt,
              void *excp_entry_table,
              size_t excp_entry_size,
              void *irq_entry_table,
              size_t irq_entry_size);

void
x64_load_idt(struct idt64 *idt);

void
x64_init_idt_bsp(void);
void
x64_init_idt_ap(void);

#endif
