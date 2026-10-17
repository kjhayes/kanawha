
#include <kanawha/kuser.h>
#include <kanawha/attribute.h>
#include <kanawha/types.h>
#include <kanawha/init.h>
#include <kanawha/errno.h>
#include <kanawha/mem_flags.h>

extern int __kuser_virt_start[];
extern int __kuser_virt_end[];
static inline void __kuser *
kuser_virt_start(void) {
    return (void __kuser *)__kuser_virt_start;
}
static inline void __kuser *
kuser_virt_end(void) {
    return (void __kuser *)__kuser_virt_end;
}
static inline size_t
kuser_virt_size(void) {
    return kuser_virt_end() - kuser_virt_start();
}

extern int __kuser_text_virt_start[];
extern int __kuser_text_virt_end[];
static inline void __kuser *
kuser_text_virt_start(void) {
    return (void __kuser *)__kuser_text_virt_start;
}
static inline void __kuser *
kuser_text_virt_end(void) {
    return (void __kuser *)__kuser_text_virt_end;
}
static inline size_t
kuser_text_virt_size(void) {
    return kuser_text_virt_end() - kuser_text_virt_start();
}

extern int __kuser_data_virt_start[];
extern int __kuser_data_virt_end[];
static inline void __kuser *
kuser_data_virt_start(void) {
    return (void __kuser *)__kuser_data_virt_start;
}
static inline void __kuser *
kuser_data_virt_end(void) {
    return (void __kuser *)__kuser_data_virt_end;
}
static inline size_t
kuser_data_virt_size(void) {
    return kuser_data_virt_end() - kuser_data_virt_start();
}

extern int __kuser_rodata_virt_start[];
extern int __kuser_rodata_virt_end[];
static inline void __kuser *
kuser_rodata_virt_start(void) {
    return (void __kuser *)__kuser_rodata_virt_start;
}
static inline void __kuser *
kuser_rodata_virt_end(void) {
    return (void __kuser *)__kuser_rodata_virt_end;
}
static inline size_t
kuser_rodata_virt_size(void) {
    return kuser_rodata_virt_end() - kuser_rodata_virt_start();
}

// Reserving the virtual memory region
static int
kuser_reserve_virtual_memory(void)
{
    int res;
    struct mem_flags *vflags = get_virt_mem_flags();
    if(vflags == NULL) {
        return -EINVAL;
    }

    res = mem_flags_reserve_region(
            vflags,
            (uintptr_t)kuser_virt_start(),
            kuser_virt_size(),
            VIRT_MEM_FLAGS_AVAIL,
            0,
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve virtual memory region %e\n",
                res);
        return res;
    }

    res = mem_flags_check_region(
            vflags,
            (uintptr_t)kuser_text_virt_start(),
            kuser_text_virt_size(),
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve .text virtual memory region %e\n",
                res);
        return res;
    }

    res = mem_flags_check_region(
            vflags,
            (uintptr_t)kuser_data_virt_start(),
            kuser_data_virt_size(),
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve .data virtual memory region %e\n",
                res);
        return res;
    }

    res = mem_flags_check_region(
            vflags,
            (uintptr_t)kuser_rodata_virt_start(),
            kuser_rodata_virt_size(),
            VIRT_MEM_FLAGS_KUSER,
            VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        eprintk("kuser: failed to reserve .rodata virtual memory region %e\n",
                res);
        return res;
    }

    return 0;
}
declare_init_desc(post_mem_flags, kuser_reserve_virtual_memory, "Reserving kuser Virtual Memory Region");

