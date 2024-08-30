#ifndef __KANAWHA__IDT_H__
#define __KANAWHA__IDT_H__

#include <kanawha/stdint.h>

/*
 * TODO: Stop using bitfields for this
 * (Bitfield order is undefined and afaik there's no way to enforce it)
 */

#define IDT64_ENTRY_FLAG_DPL_MASK 0x6000
#define IDT64_ENTRY_FLAG_DPL_RING0 0x0000
#define IDT64_ENTRY_FLAG_DPL_RING1 0x2000
#define IDT64_ENTRY_FLAG_DPL_RING2 0x4000
#define IDT64_ENTRY_FLAG_DPL_RING3 0x6000

#define IDT64_ENTRY_FLAG_PRESENT 0x8000

#define IDT64_ENTRY_FLAG_GATE_TYPE_MASK 0x0F00
#define IDT64_ENTRY_FLAG_GATE_TYPE_TRAP 0x0F00
#define IDT64_ENTRY_FLAG_GATE_TYPE_INTERRUPT 0x0E00

#define IDT64_ENTRY_FLAG_IST_MASK 0x0007
#define IDT64_ENTRY_FLAG_IST_NONE 0x0000

struct idt64_entry {
    uint16_t offset_0_15;
    uint16_t segment_selector;
    uint16_t flags;
    uint16_t offset_16_31;
    uint32_t offset_32_64;
    uint32_t __resv0_2;
} __attribute__((packed));

_Static_assert(sizeof(struct idt64_entry) == 16, "idt64_entry is not exactly 16 bytes wide!");

struct idt64 {
    struct idt64_entry exception_descriptors[32];
    struct idt64_entry interrupt_descriptors[256-32];
} __attribute__((packed));

_Static_assert(sizeof(struct idt64) == (sizeof(struct idt64_entry) * 256), "IDT64 is not the same size as 256 IDT64 entries!");

struct idt64_descriptor {
    uint16_t size;
    uint64_t offset;
} __attribute__((packed));

extern struct idt64 x64_idt64;

void x64_setup_idt_exception_entry(
        struct idt64_entry *desc,
        void *excp_entry);
void x64_setup_idt_interrupt_entry(
        struct idt64_entry *desc,
        void *irq_entry);

void x64_setup_idt(struct idt64 *idt,
        void *excp_entry_table,
        size_t excp_entry_size,
        void *irq_entry_table,
        size_t irq_entry_size);

void x64_load_idt(struct idt64 *idt);

void x64_init_idt_bsp(void);
void x64_init_idt_ap(void);

#endif
