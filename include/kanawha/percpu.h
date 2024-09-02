#ifndef __KANAWHA__PERCPU_H__
#define __KANAWHA__PERCPU_H__

#include <kanawha/cpu.h>
#include <kanawha/stdint.h>
#include <kanawha/export.h>

// "per-cpu variables"
//
// Each modules can provide a ".kpercpu" section, with data that should
// have one copy per processor in the system.
//
// The version of this section included in the statically linked portion
// of the kernel will be given to the BSP
//
// A __percpu Pointer Should NEVER be dereferenced normally, and must
// pass through one of the per-cpu macros to be used

#define __percpu_section __attribute__((section(".kpercpu")))

#ifdef CONFIG_X64
#include <arch/x64/percpu.h>
#else
#error "Architecture did not define percpu.h!"
#endif

#ifndef __arch_percpu_ptr
#error "Architecture did not define __arch_percpu_ptr in percpu.h!"
#endif
#ifndef __arch_percpu_ptr_specific
#error "Architecture did not define __arch_percpu_ptr_specific in percpu.h!"
#endif

#define __percpu __attribute__((noderef, address_space(2)))

#define DECLARE_PERCPU_VAR(__TYPE, __NAME) \
    __TYPE __percpu_section __percpu_var__ ## __NAME; \
    __TYPE __percpu * const __percpu_ptr__ ## __NAME = (__TYPE __percpu * const)&__percpu_var__ ## __NAME;

#define DECLARE_STATIC_PERCPU_VAR(__TYPE, __NAME) \
    static __TYPE __percpu_section __percpu_var__ ## __NAME; \
    static __TYPE __percpu * const __percpu_ptr__ ## __NAME = (__TYPE __percpu * const)&__percpu_var__ ## __NAME;

#define DECLARE_EXTERN_PERCPU_VAR(__TYPE, __NAME) \
    extern __TYPE __percpu * const __percpu_ptr__ ## __NAME;

#define EXPORT_PERCPU_VAR(__VAR)\
    EXPORT_SYMBOL(__percpu_var__ ## __VAR);\
    EXPORT_SYMBOL(__percpu_ptr__ ## __VAR);

#define percpu_addr(__VAR) __percpu_ptr__ ## __VAR

static inline void *
percpu_ptr(void __percpu * ptr) {
    return (void *)__arch_percpu_ptr(ptr);
}

static inline void *
percpu_ptr_specific(void __percpu *ptr, cpu_id_t cpu_id) {
    return (void *)__arch_percpu_ptr_specific(ptr, cpu_id);
}

// Set the percpu area of a remote processor, should allow percpu_ptr_specific to work
// on all processors but not necessarily percpu_ptr on processor "remote_id".
int
arch_set_percpu_area_remote(cpu_id_t remote_id, void *percpu_area);

// Assumes preemption is disabled
//
// We pass in cur_cpu_id because we cannot use current_cpu_id() until the percpu area is initialized,
// NOTE: This does not mean you can call "arch_set_percpu_area" for a remote CPU safely!
//       Once it has been called once, all calls should be semantically the same as
//       "arch_set_percpu_area(current_cpu_id(), area);"
//
int
arch_set_percpu_area(cpu_id_t cur_cpu_id, void *percpu_area);

#define PERCPU_NULL (void __percpu *)(NULL)

// Set up the percpu heap of an AP from the BSP 
int
init_cpu_percpu_data(struct cpu *cpu);

void __percpu *
percpu_alloc(size_t size);
void __percpu *
percpu_calloc(size_t size);
void
percpu_free(void __percpu *ptr, size_t size);

// Debug Assertion that a percpu Checksum is valid

#ifdef CONFIG_PERCPU_DEBUG_ASSERTIONS

#define PERCPU_DEBUG_CHECKSUM 0xCAFEBABE

DECLARE_EXTERN_PERCPU_VAR(uint64_t, __percpu_assert_checksum);

#define DEBUG_ASSERT_PERCPU_VALID() \
    do { \
        uint64_t checksum = *(uint64_t*)percpu_ptr(percpu_addr(__percpu_assert_checksum));\
        DEBUG_ASSERT((checksum >> 32) == PERCPU_DEBUG_CHECKSUM);\
    } while(0)

#else
#define DEBUG_ASSERT_PERCPU_VALID()
#endif

#endif
