#ifndef __KANAWHA__X64_GDT_H__
#define __KANAWHA__X64_GDT_H__

#define X64_GDT64_SIZE 72
#define X64_TSS_SEGMENT_SIZE 0x68ULL

#ifndef __ASSEMBLER__

#include <kanawha/stddef.h>
#include <kanawha/types.h>
#include <kanawha/percpu.h>
#include <kanawha/attribute.h>
#include <arch/x64/segdesc.h>

struct __packed gdt64_descriptor {
    uint16_t limit;
    uint64_t address;
};

_Static_assert(sizeof(struct gdt64_descriptor) == 10, "sizeof(struct gdt64_segment) is not exactly 10 bytes!");

struct __packed gdt64 {
    struct gdt64_segment null;
    struct gdt64_segment kernel_code;
    struct gdt64_segment kernel_data;
    struct gdt64_system_segment tss;
    struct gdt64_segment user_data;
    struct gdt64_segment user_code;
    struct gdt64_call_gate syscall_call_gate;
};

_Static_assert(sizeof(struct gdt64) == X64_GDT64_SIZE, "struct gdt64 does not match X64_GDT64_SIZE macro!");

#define X64_NULL_GDT_SEGMENT_OFFSET              offsetof(struct gdt64, null)
#define X64_KERNEL_CODE_GDT_SEGMENT_OFFSET       offsetof(struct gdt64, kernel_code)
#define X64_KERNEL_DATA_GDT_SEGMENT_OFFSET       offsetof(struct gdt64, kernel_data)
#define X64_TSS_GDT_SEGMENT_OFFSET               offsetof(struct gdt64, tss)
#define X64_USER_CODE_GDT_SEGMENT_OFFSET         offsetof(struct gdt64, user_code)
#define X64_USER_DATA_GDT_SEGMENT_OFFSET         offsetof(struct gdt64, user_data)
#define X64_SYSCALL_CALL_GATE_GDT_SEGMENT_OFFSET offsetof(struct gdt64, syscall_call_gate)

#define X64_SEGMENT_SELECTOR(\
	__OFFSET,\
	__USE_LDT,\
	__RING) \
    (((__OFFSET & ~0b111) | ((!!__USE_LDT)<<2) | (__RING & 0b11)) & 0xFFFFU)


static inline uint16_t
x64_segment_selector(uint16_t segment_offset, int use_ldt, int ring)
{
    return X64_SEGMENT_SELECTOR(segment_offset, use_ldt, ring);
}

extern struct gdt64 x64_bsp_gdt64;
extern uint8_t x64_bsp_tss_data[X64_TSS_SEGMENT_SIZE];

void x64_init_gdt_bsp(void);
void x64_init_gdt_ap(void);

void __percpu *
x64_percpu_tss_segment(void);

#endif

#endif
