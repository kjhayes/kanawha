
#include <kanawha/dev/term.h>
#include <drivers/vga/legacy.h>

struct legacy_vga_term {
    struct term_dev term_dev;
    uint8_t attr;
};

static int
legacy_vga_term_dev_putc(
        struct term_dev *term_dev,
        char c)
{
    struct legacy_vga_term *t =
        container_of(term_dev, struct legacy_vga_term, term_dev);
    legacy_vga_putchar(c, t->attr);
    return 0;
}

static int
legacy_vga_term_dev_flush(
        struct term_dev *term_dev)
{
    struct legacy_vga_term *t = container_of(term_dev, struct legacy_vga_term, term_dev);
    return 0;
}

static struct term_driver
legacy_vga_term_driver = {
    .putc = legacy_vga_term_dev_putc,
    .flush = legacy_vga_term_dev_flush,
    .get_baudrate = term_dev_cannot_get_baudrate,
    .set_baudrate = term_dev_cannot_set_baudrate,
};

static struct legacy_vga_term legacy_term = {0};

static int
legacy_vga_term_dev_init(void)
{
    legacy_term.attr = LEGACY_VGA_ATTR(
            LEGACY_VGA_ATTR_CYAN,
            LEGACY_VGA_ATTR_BLACK);
    legacy_term.term_dev.driver = &legacy_vga_term_driver;
    return register_term_dev(&legacy_term.term_dev, "vga");
}
declare_init_desc(device, legacy_vga_term_dev_init, "Registering Legacy VGA Pseudo-Terminal");

