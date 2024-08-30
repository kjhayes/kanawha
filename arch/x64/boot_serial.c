
#include <kanawha/pio.h>
#include <kanawha/printk.h>
#include <kanawha/init.h>

static void
x64_boot_serial_printk_early_handler(char c) {
    // HACK
#define SERIAL_PORT 0x3f8
    while((inb(SERIAL_PORT+5) & 0x20) == 0);
    outb(SERIAL_PORT,c);
}

int x64_boot_serial_init(void) 
{
    int res;
    res = printk_early_add_handler(x64_boot_serial_printk_early_handler);
    return res;
}

declare_init_desc(boot, x64_boot_serial_init, "Registering Boot Serial Port");

