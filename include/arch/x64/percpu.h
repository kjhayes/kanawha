#ifndef __KANAWHA__X64_PERCPU_H__
#define __KANAWHA__X64_PERCPU_H__

#include <kanawha/stdint.h>
#include <kanawha/cpu.h>

// Locations in this structure need to be fixed,
// because they can be accessed from assembly
struct x64_percpu_data {
    // Offset used to calculate percpu variable accesses
    void *percpu_offset; // Offset 0
    // Scratch percpu register which can be used in special circumstances
    uint64_t scratch; // Offset 8
}
__attribute__((packed));


extern struct x64_percpu_data
__x64_percpu_data[CONFIG_MAX_CPUS];

#define __arch_percpu_ptr(ptr) \
    ({\
     uintptr_t segment_offset;\
     asm volatile("movq %%gs:0, %0" : "=r" (segment_offset));\
     void *global_ptr = ((void*)ptr) + (uintptr_t)segment_offset;\
     dprintk("percpu_ptr(%p) -> %p\n", ptr, global_ptr);\
     (typeof(ptr))global_ptr;\
     })

#define __arch_percpu_ptr_specific(ptr, cpu_id) \
    ({\
     void *ptr_spec = (typeof(ptr)*)(__x64_percpu_data[cpu_id].percpu_offset + (uintptr_t)ptr);\
     dprintk("percpu_ptr_specific(%p, %ld) -> %p\n",\
             (void*)ptr, (unsigned long)cpu_id, ptr_spec);\
     ptr_spec;\
     })

#endif
