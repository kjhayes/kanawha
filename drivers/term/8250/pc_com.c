
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/pio.h>
#include <drivers/term/8250/common.h>
#include <arch/x64/pic.h>

#define PC_COM_MAX_NAMELEN 8

struct pc_com
{
    int index;
    struct uart_8250 uart_8250;

    pio_t base_port;

    char name[PC_COM_MAX_NAMELEN+1];
};

#define NUM_PLATFORM_PC_COM_PORTS 2
static struct pc_com
platform_pc_com_ports[NUM_PLATFORM_PC_COM_PORTS];

static pio_t
platform_pc_com_ports_base[] =
{
    0x3F8,
    0x2F8,
    0x3E8,
    0x2E8,
    0x5F8,
    0x4F8,
    0x5E8,
    0x4E8,
};
static hwirq_t
platform_pc_com_pic_irq[] =
{
    4,
    3,
    4,
    3,
};


static void
pc_com_set_dlab(
        struct pc_com *com,
        int dlab)
{
    uint8_t icr = inb(com->base_port + 3);
    icr &= ~(1<<7);
    icr |= (!!dlab)<<7;
    outb(com->base_port + 3, icr);
}

static pio_t
pc_com_enable_reg_port(
        struct uart_8250 *uart,
        reg_8250_t reg)
{
    struct pc_com *com =
        container_of(uart, struct pc_com, uart_8250);

    switch(reg) {
        case UART_8250_RBR:
        case UART_8250_THR:
        case UART_8250_IER:
            pc_com_set_dlab(com, 0);
            break;
        case UART_8250_DLL:
        case UART_8250_DLM:
            pc_com_set_dlab(com, 1);
            break;
        default:
            break;
    }

    pio_t pio_offset;
    switch(reg) {
        case UART_8250_RBR:
        case UART_8250_THR:
        case UART_8250_DLL:
            pio_offset = 0;
            break;
        case UART_8250_IER:
        case UART_8250_DLM:
            pio_offset = 1;
            break;
        case UART_8250_IIR:
        case UART_8250_FCR:
            pio_offset = 2;
            break;
        case UART_8250_LCR:
            pio_offset = 3;
            break;
        case UART_8250_MCR:
            pio_offset = 4;
            break;
        case UART_8250_LSR:
            pio_offset = 5;
            break;
        case UART_8250_MSR:
            pio_offset = 6;
            break;
        case UART_8250_SCR:
            pio_offset = 7;
            break;
    }

    return com->base_port + pio_offset;
}

static uint8_t
pc_com_8250_read_reg(
        struct uart_8250 *uart,
        reg_8250_t reg)
{
    pio_t port = pc_com_enable_reg_port(uart, reg);
    return inb(port);
}

static int
pc_com_8250_write_reg(
        struct uart_8250 *uart,
        reg_8250_t reg,
        uint8_t value)
{
    pio_t port = pc_com_enable_reg_port(uart, reg);
    outb(port, value);
    return 0;
}

static struct uart_8250_ops
pc_com_8250_uart_ops = {
    .read_reg = pc_com_8250_read_reg,
    .write_reg = pc_com_8250_write_reg,
    .set_irqs_enabled = generic_8250_set_irqs_enabled,
    .set_recv_trigger = generic_8250_set_recv_trigger,
};

static int
pc_com_8250_register(
        struct pc_com *com,
        int index)
{
    int res;

    com->index = index;
    com->base_port = platform_pc_com_ports_base[index];
    com->uart_8250.irq = x64_pic_irq(platform_pc_com_pic_irq[index]);

    snprintk(com->name, PC_COM_MAX_NAMELEN, "COM%ld", (sl_t)index+1);
    com->name[PC_COM_MAX_NAMELEN] = '\0';

    res = register_uart_8250(
            com->name,
            &com->uart_8250,
            &pc_com_8250_uart_ops,
            NULL, // Use generic 8250 char dev and uart drivers
            NULL,
	    NULL);
    if(res) {
        return res;
    }

    return 0;
}

static int
pc_com_8250_init(void)
{
    int res;

    for(int i = 0; i < NUM_PLATFORM_PC_COM_PORTS; i++) {
        res = pc_com_8250_register(&platform_pc_com_ports[i], i);
        if(res != 0 && res != -ENODEV) {
            return res;
        }
    }

    return 0;
}
declare_init_desc(device, pc_com_8250_init, "Registering PC COM Serial Port(s)");

