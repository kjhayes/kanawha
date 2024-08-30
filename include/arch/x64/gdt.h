#ifndef __KANAWHA__X64_GDT_H__
#define __KANAWHA__X64_GDT_H__

#define X64_GDT64_SIZE 48
#define X64_TSS_SEGMENT_SIZE 0x68ULL

#ifndef __ASSEMBLER__

#include <kanawha/stddef.h>
#include <kanawha/stdint.h>
#include <kanawha/percpu.h>

struct gdt64_segment {
  union {
    uint64_t raw;
    struct {
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
    } __attribute__((packed));
  };
} __attribute__((packed));
_Static_assert(sizeof(struct gdt64_segment) == 8, "sizeof(struct gdt64_segment) is not exactly 8 bytes!");

#define X64_GDT_SYSTEM_SEGMENT_TYPE_TSS 0b1001

struct gdt64_system_segment {
  union {
    struct {
      uint64_t raw_low;
      uint64_t raw_high;
    } __attribute((packed));
    struct {
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
    } __attribute__((packed));
  };
} __attribute__((packed));
_Static_assert(sizeof(struct gdt64_system_segment) == 16, "sizeof(struct gdt64_system_segment) is not exactly 16 bytes!");

struct gdt64_descriptor {
    uint16_t limit;
    uint64_t address;
} __attribute__((packed));

_Static_assert(sizeof(struct gdt64_descriptor) == 10, "sizeof(struct gdt64_segment) is not exactly 10 bytes!");

struct gdt64 {
    struct gdt64_segment null;
    struct gdt64_segment kernel_code;
    struct gdt64_segment kernel_data;
    struct gdt64_system_segment tss;
    struct gdt64_segment user_data;
    struct gdt64_segment user_code;
} __attribute__((packed));

#define X64_NULL_GDT_SEGMENT_OFFSET        offsetof(struct gdt64, null)
#define X64_KERNEL_CODE_GDT_SEGMENT_OFFSET offsetof(struct gdt64, kernel_code)
#define X64_KERNEL_DATA_GDT_SEGMENT_OFFSET offsetof(struct gdt64, kernel_data)
#define X64_TSS_GDT_SEGMENT_OFFSET         offsetof(struct gdt64, tss)
#define X64_USER_CODE_GDT_SEGMENT_OFFSET   offsetof(struct gdt64, user_code)
#define X64_USER_DATA_GDT_SEGMENT_OFFSET   offsetof(struct gdt64, user_data)

static inline uint16_t
x64_segment_selector(uint16_t segment_offset, int use_ldt, int ring) {
    return (segment_offset & ~0b111) | ((!!use_ldt)<<2) | (ring & 0b11);
}

extern struct gdt64 x64_bsp_gdt64;
extern uint8_t x64_bsp_tss_data[X64_TSS_SEGMENT_SIZE];

void x64_init_gdt_bsp(void);
void x64_init_gdt_ap(void);

void __percpu *
x64_percpu_tss_segment(void);

#endif

#endif
