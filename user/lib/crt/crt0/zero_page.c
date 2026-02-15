
#include <kanawha/sys-wrappers.h>
#include <kanawha/mmap.h>

int __elk_crt__map_zero_page(void) {
    void *addr = NULL;
    kanawha_sys_mmap(
            0,
            0,
            &addr,
            0x1000,
            MMAP_ANON|MMAP_PROT_READ|MMAP_EXACT);
    return 0;
}

