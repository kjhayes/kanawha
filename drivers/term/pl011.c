
#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/vmem.h>
#include <kanawha/init.h>

#define PL011_REG_DR    (0x000)
#define PL011_REG_RSR   (0x004)
#define PL011_REG_ECR   (0x004)
#define PL011_REG_FR    (0x018)
#define PL011_REG_ILPR  (0x020)
#define PL011_REG_IBRD  (0x024)
#define PL011_REG_FBRD  (0x028)
#define PL011_REG_LCR_H (0x02C)
#define PL011_REG_CR    (0x030)
#define PL011_REG_IFLS  (0x034)
#define PL011_REG_IMSC  (0x038)
#define PL011_REG_RIS   (0x03C)
#define PL011_REG_MIS   (0x040)
#define PL011_REG_ICR   (0x044)
#define PL011_REG_DMACR (0x048)
#define PL011_REG_PeriphID0 (0xFE0)
#define PL011_REG_PeriphID1 (0xFE4)
#define PL011_REG_PeriphID2 (0xFE8)
#define PL011_REG_PeriphID3 (0xFEC)
#define PL011_REG_PCellID0  (0xFF0)
#define PL011_REG_PCellID1  (0xFF4)
#define PL011_REG_PCellID2  (0xFF8)
#define PL011_REG_PCellID3  (0xFFC)


#ifdef CONFIG_PL011_SERIAL_AT_BOOT

#define pl011_boot_regbase() \
    ((volatile uint8_t *)(__va((void __phys *)(uintptr_t)CONFIG_PL011_SERIAL_AT_BOOT_ADDR)))

#define pl011_boot_read(__offset) \
    (*(volatile uint32_t*)(pl011_boot_regbase() + (__offset)))

#define pl011_boot_write(__offset, __value) \
    do {\
        (*(volatile uint32_t*)(pl011_boot_regbase() + (__offset))) = (__value); \
    } while(0)

static int
pl011_boot_printk_handler(char c)
{
    uint32_t value = c;
    pl011_boot_write(PL011_REG_DR, value);
    return 0;
}

static int
pl011_boot_init(void)
{
    int res;

    { // Turn on the UART
        uint32_t cr = pl011_boot_read(PL011_REG_CR);
        cr |= 0b1; // UARTEN
        pl011_boot_write(PL011_REG_CR, cr);
    }

    res = printk_add_handler(pl011_boot_printk_handler);
    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(boot, pl011_boot_init, "Registering Boot PL011 Serial");

#endif

