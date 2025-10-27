#ifndef __KANAWHA__ARCH_X64_SEGDESC_H__
#define __KANAWHA__ARCH_X64_SEGDESC_H__

#include <kanawha/types.h>
#include <kanawha/attribute.h>

#define X64_SEGMENT_TYPE_CALL_GATE      (0xC)
#define X64_SEGMENT_TYPE_INTERRUPT_GATE (0xE)
#define X64_SEGMENT_TYPE_TRAP_GATE      (0xF)

#define IDT64_ENTRY_FLAG_DPL_MASK 0x6000
#define IDT64_ENTRY_FLAG_DPL_RING0 0x0000
#define IDT64_ENTRY_FLAG_DPL_RING1 0x2000
#define IDT64_ENTRY_FLAG_DPL_RING2 0x4000
#define IDT64_ENTRY_FLAG_DPL_RING3 0x6000

#define IDT64_ENTRY_FLAG_PRESENT 0x8000

#define IDT64_ENTRY_FLAG_GATE_TYPE_MASK      (0xF<<8)
#define IDT64_ENTRY_FLAG_GATE_TYPE_TRAP      ((X64_SEGMENT_TYPE_TRAP_GATE & 0xF) << 8)
#define IDT64_ENTRY_FLAG_GATE_TYPE_INTERRUPT ((X64_SEGMENT_TYPE_INTERRUPT_GATE & 0xF) << 8)

#define IDT64_ENTRY_FLAG_IST_MASK 0x0007
#define IDT64_ENTRY_FLAG_IST_NONE 0x0000

struct __packed idt64_entry {
    uint16_t offset_0_15;
    uint16_t segment_selector;
    uint16_t flags;
    uint16_t offset_16_31;
    uint32_t offset_32_64;
    uint32_t __resv0_2;
};

_Static_assert(sizeof(struct idt64_entry) == 16, "idt64_entry is not exactly 16 bytes wide!");

/*
 * TODO: Stop using bitfields for this
 * (Bitfield order is undefined and afaik there's no way to enforce it)
 */

struct __packed gdt64_segment {
  union {
    uint64_t raw;
    struct __packed {
      uint16_t limit_low_16 : 16;
      uint32_t base_low_24 : 24;
      uint8_t accessed : 1;
      uint8_t read_write : 1;
      uint8_t conforming : 1;
      uint8_t executable : 1;
      uint8_t mb1 : 1;
      uint8_t ring : 2;
      uint8_t present : 1;
      uint8_t limit_middle_4 : 4;
      uint8_t avail : 1;
      uint8_t long_mode : 1;
      uint8_t sz_32 : 1;
      uint8_t granularity : 1;
      uint8_t base_high_8 : 8;
    };
  };
};
_Static_assert(sizeof(struct gdt64_segment) == 8, "sizeof(struct gdt64_segment) is not exactly 8 bytes!");

#define X64_GDT_SYSTEM_SEGMENT_TYPE_TSS 0b1001

struct __packed gdt64_system_segment {
  union {
    struct __packed {
      uint64_t raw_low;
      uint64_t raw_high;
    };
    struct __packed {
      uint16_t limit_low_16 : 16;
      uint32_t base_low_24 : 24;
      uint8_t type : 4;
      uint8_t mb0 : 1;
      uint8_t ring : 2;
      uint8_t present : 1;
      uint8_t limit_middle_4 : 4;
      uint8_t avail : 1;
      uint8_t __resv0_0 : 2;
      uint8_t granularity : 1;
      uint64_t base_high_40 : 40;
      uint32_t __resv0_1 : 32;
    };
  };
};
_Static_assert(sizeof(struct gdt64_system_segment) == 16, "sizeof(struct gdt64_system_segment) is not exactly 16 bytes!");

// This structure is only defined explicitly by AMD
// as far as I can tell -KJH
struct __packed gdt64_call_gate {
    uint16_t target_offset_15_0;
    uint16_t target_selector;
    uint8_t __resv0_0;
    uint8_t type : 4;
    uint8_t __resv0_1 : 1;
    uint8_t ring: 2;
    uint8_t present: 1;
    uint16_t target_offset_31_16;
    uint32_t target_offset_63_32;
    uint32_t __resv0_2;
};
_Static_assert(sizeof(struct gdt64_call_gate) == 16, "sizeof(struct gdt64_system_segment) is not exactly 16 bytes!");

#endif
