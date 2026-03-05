
#include <stdint.h>
#include <string.h>

extern int __bss_start[];

/*
 * FIXME: Given the current linker script GCC provides us, we don't get any
 *        info about the end of .bss other than the end of the entire program
 * "_end" But if the "large" data segments (.ldata, .lrodata) are included,
 * we'll end up zero-ing them out because they would sit between the end of bss
 * and _end) We should modify the linker script so that this isn't an issue
 * (but I don't want to sit around re-compiling gcc right now)
 */
extern int _end[];

#define BSS_START ((void *)__bss_start)
#define BSS_END ((void *)_end)
#define BSS_SIZE (BSS_END - BSS_START)

int
__elk_crt__clear_bss(void)
{

    memset(BSS_START, 0, BSS_SIZE);
    return 0;
}
