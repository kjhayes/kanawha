
#include <kanawha/printk.h>
#include <kanawha/klog.h>
#include <kanawha/init.h>
#include <kanawha/errno.h>
#include <kanawha/percpu.h>
#include <kanawha/vmem.h>
#include <kanawha/thread.h>
#include <kanawha/irq_domain.h>
#include <kanawha/clk.h>
#include <kanawha/string.h>
#include <kanawha/usermode.h>
#include <arch/riscv64/mem_flags.h>

#include <devicetree/devicetree.h>

static void
clear_bss(void) {

extern uint8_t __kernel_bss_start[];
extern uint8_t __kernel_bss_end[];

    memset(
        (void*)&__kernel_bss_start,
        0,
        (uintptr_t)&__kernel_bss_end - (uintptr_t)&__kernel_bss_start);
}
static void
clear_percpu(void) {

extern uint8_t __builtin_kpercpu_start[];
extern uint8_t __builtin_kpercpu_end[];

    memset(
        (void*)&__builtin_kpercpu_start,
        0,
        (uintptr_t)&__builtin_kpercpu_end - (uintptr_t)&__builtin_kpercpu_start);
}

void *
riscv64_boot_bsp_init(
        void __phys *kernel_phys_base,
        struct fdt __phys *dtb,
        uint64_t hartid,
        void * identity_map_base)
{
    int res;

    clear_bss();
    clear_percpu();

    __riscv64_identity_map_offset = (size_t)identity_map_base;

    klog_init();
    printk_init();

    res = handle_init_stage__boot();
    if(res) {
        panic("Failed to handle init stage \"boot\"! err=%s", errnostr(res));
    }

    printk("Booting on HARTID=0x%lx\n", hartid);

    res = riscv64_provide_kernel_phys_base(kernel_phys_base);
    if(res) {
        panic("Failed to provide kernel physical base!\n");
    }
    printk("Provided Kernel Physical Base = %p\n", kernel_phys_base);

    res = devicetree_provide_dtb(dtb);
    if(res) {
        panic("Kernel rejected provided device tree!\n");
    }
    printk("Provided Device Tree = %p\n", dtb);

    res = handle_init_stage__static();
    if(res) {
        panic("Failed to handle init stage \"static\"! err=%s", errnostr(res));
    }

    printk("Initializing the kernel...\n");

    // mem_flags Init Stages
    res = handle_init_stage__mem_flags();
    if(res) {
        panic("Failed to handle init stage \"mem_flags\"! err=%s", errnostr(res));
    }
    res = handle_init_stage__post_mem_flags();
    if(res) {
        panic("Failed to handle init stage \"post_mem_flags\"! err=%s", errnostr(res));
    }

    // At this point both __va and __pa should be stable
    return __va(0);
}

// Here we should be running fully virtually
void
riscv64_virtual_bsp_init(void)
{
    int res;

    // alloc Init Stages
    res = handle_init_stage__page_alloc();
    if(res) {
        panic("Failed to handle init stage \"page_alloc\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__dynamic_page();
    if(res) {
        panic("Failed to handle init stage \"dynamic_page\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__vmem();
    if(res) {
        panic("Failed to handle init stage \"vmem\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__enable_vmem();
    if(res) {
        panic("Failed to handle init stage \"enable_vmem\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__post_vmem();
    if(res) {
        panic("Failed to handle init stage \"post_vmem\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__kmalloc();
    if(res) {
        panic("Failed to handle init stage \"kmalloc\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__dynamic();
    if(res) {
        panic("Failed to handle init stage \"dynamic\"! err=%s", errnostr(res));
    }

    extern void riscv64_init(void*);
    cpu_start_threading(riscv64_init, NULL);

    panic("Failed to start threading on BSP!\n");
}

void
riscv64_init(void *in)
{
    int res;

    printk("Started threading on CPU (%ld)\n",
            (long)current_cpu_id());

    while(1) {}
}

