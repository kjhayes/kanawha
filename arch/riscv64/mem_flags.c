
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/printk.h>

#include <arch/riscv64/mmu.h>

extern uint8_t __kernel_virt_start[];
extern uint8_t __kernel_virt_end[];
static void __phys *kernel_virt_start = (void __phys *)&__kernel_virt_start;
static void __phys *kernel_virt_end = (void __phys *)&__kernel_virt_end;

extern uint8_t __kernel_boot_start[];
extern uint8_t __kernel_boot_end[];
static void __phys *volatile kernel_boot_start =
    (void __phys *)__kernel_boot_start;
static void __phys *volatile kernel_boot_end = (void __phys *)__kernel_boot_end;

size_t __riscv64_identity_map_offset = 0;
static void __phys *kernel_phys_base = NULL;

int
riscv64_provide_kernel_phys_base(void __phys *base)
{
    kernel_phys_base = base;
    return 0;
}

void __phys *
arch_kernel_phys_start(void)
{
    return kernel_phys_base;
}
size_t
arch_kernel_phys_size(void)
{
    return ((size_t)((uintptr_t)kernel_virt_end -
                     (uintptr_t)kernel_virt_start)) +
           ((size_t)((uintptr_t)kernel_boot_end -
                     (uintptr_t)kernel_boot_start));
}

static int
riscv64_virt_flags_static_init(void)
{
    int res;

    struct mem_flags *vflags = get_virt_mem_flags();

#if defined(CONFIG_RISCV64_SV57)
#define HIGHMEM_BASE (~((1ULL << (57 - 1)) - 1))
#define HIGHMEM_SIZE (1ULL << (57 - 1))
#define LOWMEM_BASE 0x0
#define LOWMEM_SIZE (1ULL << (57 - 1))
#elif defined(CONFIG_RISCV64_SV48)
#define HIGHMEM_BASE (~((1ULL << (48 - 1)) - 1))
#define HIGHMEM_SIZE (1ULL << (48 - 1))
#define LOWMEM_BASE 0x0
#define LOWMEM_SIZE (1ULL << (48 - 1))
#elif defined(CONFIG_RISCV64_SV39)
#define HIGHMEM_BASE (~((1ULL << (39 - 1)) - 1))
#define HIGHMEM_SIZE (1ULL << (39 - 1))
#define LOWMEM_BASE 0x0
#define LOWMEM_SIZE (1ULL << (39 - 1))
#else
#error                                                                         \
    "One of CONFIG_RISCV64_SV39, CONFIG_RISCV64_SV48 or CONFIG_RISCV64_SV57 must be set!"
#endif

    printk("Setting Region [%p - %p) as Canonical Low Memory\n",
           LOWMEM_BASE,
           LOWMEM_BASE + LOWMEM_SIZE);

    res = mem_flags_clear_flags(vflags,
                                LOWMEM_BASE,
                                LOWMEM_SIZE,
                                VIRT_MEM_FLAGS_NONCANON);
    if(res)
    {
        return res;
    }

    printk("Setting Region [%p - %p) as Canonical High Memory\n",
           HIGHMEM_BASE,
           HIGHMEM_BASE + (HIGHMEM_SIZE - 1));

    res = mem_flags_clear_flags(vflags,
                                HIGHMEM_BASE,
                                HIGHMEM_SIZE - 1,
                                VIRT_MEM_FLAGS_NONCANON);
    if(res)
    {
        return res;
    }

    res = mem_flags_set_flags(vflags,
                              HIGHMEM_BASE,
                              HIGHMEM_SIZE - 1,
                              VIRT_MEM_FLAGS_HIGHMEM);
    if(res)
    {
        return res;
    }

    // Reserve the kernel in high-mem
    printk("Reserving the Kernel in Virtual Memory [%p - %p)\n",
           __kernel_virt_start,
           __kernel_virt_end);
    res = mem_flags_check_region(vflags,
                                 (uintptr_t)__kernel_virt_start,
                                 (__kernel_virt_end - __kernel_virt_start),
                                 VIRT_MEM_FLAGS_AVAIL | VIRT_MEM_FLAGS_HIGHMEM,
                                 0);
    if(res)
    {
        eprintk("Failed to reserve kernel in virtual memory! (err=%s)\n",
                errnostr(res));
        virt_mem_flags_dump();
        return res;
    }

    res = mem_flags_clear_flags(vflags,
                                (uintptr_t)__kernel_virt_start,
                                (__kernel_virt_end - __kernel_virt_start),
                                VIRT_MEM_FLAGS_AVAIL);

    // Reserve the high-mem identity map
    printk("Reserving the Kernel Identity Map [%p - %p)",
           __riscv64_identity_map_offset,
           __riscv64_identity_map_offset +
               (1ULL << CONFIG_RISCV64_IDENTITY_MAP_ORDER));

    res = mem_flags_check_region(vflags,
                                 __riscv64_identity_map_offset,
                                 (1ULL << CONFIG_RISCV64_IDENTITY_MAP_ORDER),
                                 VIRT_MEM_FLAGS_AVAIL | VIRT_MEM_FLAGS_HIGHMEM,
                                 0);
    if(res)
    {
        eprintk("Failed to reserve high-mem identity map! (err=%s)\n",
                errnostr(res));
        virt_mem_flags_dump();
        return res;
    }

    res = mem_flags_clear_flags(vflags,
                                __riscv64_identity_map_offset,
                                (1ULL << CONFIG_RISCV64_IDENTITY_MAP_ORDER),
                                VIRT_MEM_FLAGS_AVAIL);

    return 0;
}
declare_init_desc(mem_flags,
                  riscv64_virt_flags_static_init,
                  "Setting RISC-V Virtual Memory Types");
