
#include <drivers/vga/legacy.h>
#include <kanawha/init.h>
#include <kanawha/printk.h>

#define LEGACY_VGA_PRINTK_EARLY_ATTR \
    LEGACY_VGA_ATTR(LEGACY_VGA_ATTR_ORANGE, LEGACY_VGA_ATTR_BLACK)

static int
legacy_vga_printk_handler(char c)
{
    legacy_vga_putchar(c, LEGACY_VGA_PRINTK_EARLY_ATTR);
    return 0;
}

static int
legacy_vga_boot_init(void)
{
    int res;
    legacy_vga_clear(' ', LEGACY_VGA_PRINTK_EARLY_ATTR);
    res = printk_add_handler(legacy_vga_printk_handler);
    return res;
}
declare_init_desc(boot, legacy_vga_boot_init, "Registering Legacy VGA Boot Handler");

#ifndef CONFIG_LEGACY_VGA_TERMINAL_PRINTK
static int
legacy_vga_boot_deinit(void)
{
    return printk_remove_handler(legacy_vga_printk_handler);
}
declare_init_desc(platform, legacy_vga_boot_deinit, "Deregistering Legacy VGA Boot Handler");
#endif

