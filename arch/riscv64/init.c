
#include <kanawha/printk.h>
#include <kanawha/klog.h>
#include <kanawha/init.h>
#include <kanawha/errno.h>
#include <kanawha/percpu.h>
#include <kanawha/vmem.h>
#include <kanawha/thread.h>
#include <kanawha/irq_domain.h>
#include <kanawha/clk.h>
#include <kanawha/usermode.h>

void *
riscv64_boot_bsp_init(void)
{
    int res;

    while(1) {}

    klog_init();
    printk_init();

    res = handle_init_stage__boot();
    if(res) {
        panic("Failed to handle init stage \"boot\"! err=%s", errnostr(res));
    }

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

    // alloc Init Stages
    res = handle_init_stage__page_alloc();
    if(res) {
        panic("Failed to handle init stage \"page_alloc\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__vmem();
    if(res) {
        panic("Failed to handle init stage \"vmem\"! err=%s", errnostr(res));
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

    printk("Should start threading here...\n");

    while(1) {}
}

