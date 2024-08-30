
#include <kanawha/pio.h>
#include <kanawha/irq.h>
#include <kanawha/init.h>

// We need to remap these in-case a spurrious
// interrupt leaks through the mask
// (They are mapped over exception vectors by default)
#define PIC0_VECTOR_BASE 0x32
#define PIC1_VECTOR_BASE 0x3A

#define PIC0_CMD  0x20
#define PIC0_DATA 0x21
#define PIC1_CMD  0xA0
#define PIC1_DATA 0xA1

#define PIC_OCW_EOI 0x20

#define PIC_ICW1      0x10
#define PIC_ICW1_ICW4 0x01

#define PIC_ICW4_8086 0x01

static int
x64_init_and_disable_pic(void)
{
    // Make sure IRQ's are not enabled during this
    int irq_state = disable_save_irqs();

    // ICW1
    outb(PIC0_CMD, PIC_ICW1 | PIC_ICW1_ICW4);
    piodelay();
    outb(PIC1_CMD, PIC_ICW1 | PIC_ICW1_ICW4);
    piodelay();

    // ICW2 (vectors)
    outb(PIC0_DATA, PIC0_VECTOR_BASE);
    piodelay();
    outb(PIC1_DATA, PIC1_VECTOR_BASE);
    piodelay();


    // ICW3 (cascade info)
    outb(PIC0_DATA, 4);
    piodelay();
    outb(PIC1_DATA, 2);
    piodelay();

    // ICW4 (mode setting)
    outb(PIC0_DATA, PIC_ICW4_8086);
    piodelay();
    outb(PIC1_DATA, PIC_ICW4_8086);
    piodelay();

    // Mask the PIC(s)
    outb(PIC0_DATA, 0xFF);
    piodelay();
    outb(PIC1_DATA, 0xFF);
    piodelay();

    enable_restore_irqs(irq_state);

    return 0;
}
declare_init_desc(static, x64_init_and_disable_pic, "Disabling 8259 PIC");

