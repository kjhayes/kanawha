
#include <kanawha/pio.h>
#include <kanawha/printk.h>
#include <kanawha/init.h>

static int
x64_boot_serial_printk_handler(char c) {
    // HACK
#define SERIAL_PORT 0x3f8
    while((inb(SERIAL_PORT+5) & 0x20) == 0);
    outb(SERIAL_PORT,c);
    return 0;
}

int x64_boot_serial_init(void) 
{
    int res;
    res = printk_add_handler(x64_boot_serial_printk_handler);
    return res;
}

declare_init_desc(boot, x64_boot_serial_init, "Registering Boot Serial Port");

#ifndef CONFIG_X64_BOOT_SERIAL_POST_LAUNCH
int x64_boot_serial_deinit(void) 
{
    int res;
    res = printk_remove_handler(x64_boot_serial_printk_handler);
    return res;
}
declare_init_desc(platform, x64_boot_serial_deinit, "Deregistering Boot Serial");
#endif
