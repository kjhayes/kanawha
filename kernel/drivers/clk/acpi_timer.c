
#include <kanawha/clk_dev.h>
#include <kanawha/clk.h>
#include <kanawha/init.h>
#include <kanawha/mmio.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/irq.h>
#include <acpi/acpi.h>
#include <acpi/table.h>
#include <acpi/gas.h>
#include <acpi/fadt.h>

#ifdef CONFIG_PORT_IO
#include <kanawha/pio.h>
#endif

#define ACPI_PM_TIMER_FREQ_HZ (hz_t)3579545

static freq_t
acpi_pm_timer_freq(struct clk_dev *dev) {
    return hz_to_freq(ACPI_PM_TIMER_FREQ_HZ);
}

struct acpi_pm_timer
{
    struct clk_dev clk_dev;
    union {
        struct {
            void __mmio *blk;
        } mmio;

#ifdef CONFIG_PORT_IO
        struct {
            pio_t port;
        } pio;
#endif
    };
};

#ifdef CONFIG_PORT_IO
static cycles_t
acpi_pm_timer_cycles_port(struct clk_dev *clk_dev)
{
    struct acpi_pm_timer *pm =
        container_of(clk_dev, struct acpi_pm_timer, clk_dev);

    return (cycles_t)inl(pm->pio.port);
}
#endif

static cycles_t
acpi_pm_timer_cycles_mmio(struct clk_dev *clk_dev)
{
    struct acpi_pm_timer *pm =
        container_of(clk_dev, struct acpi_pm_timer, clk_dev);

    return (cycles_t)mmio_readl(pm->mmio.blk);
}


#ifdef CONFIG_PORT_IO
static struct clk_driver
acpi_pm_clk_driver_port = {
    .freq = acpi_pm_timer_freq,
    .mono_cycles = acpi_pm_timer_cycles_port,
};
#endif

static struct clk_driver
acpi_pm_clk_driver_mmio = {
    .freq = acpi_pm_timer_freq,
    .mono_cycles = acpi_pm_timer_cycles_mmio,
};


static int
init_acpi_pm_timer_clk(void)
{
    struct acpi_table_hdr *hdr = acpi_find_table(FADT_SIG_STRING);
    if(hdr == NULL) {
        printk("Could not find ACPI FADT Table to initialize ACPI PM Timer\n");
        return 0;
    }

    struct acpi_fadt *fadt = (struct acpi_fadt*)hdr;

    struct acpi_pm_timer *clk = kmalloc(sizeof(struct acpi_pm_timer));
    if(clk == NULL) {
        eprintk("Failed to allocate ACPI PM Timer\n");
        return -ENOMEM;
    }
    memset(clk, 0, sizeof(struct acpi_pm_timer));

    printk("Found FADT (%p)\n", fadt);

    if(acpi_revision() >= 2
            && fadt->x_pm_tmr_blk.address != 0
            && fadt->x_pm_tmr_blk.access_size == 4)
    {
        printk("Using Generic Address Structure for PM Timer Block\n");
        switch(fadt->x_pm_tmr_blk.asid) {
            case ACPI_GAS_ASID_MMIO:
                clk->mmio.blk = mmio_map((void __phys *)fadt->x_pm_tmr_blk.address, 4);
                if(clk->mmio.blk == NULL) {
                    eprintk("Failed to map MMIO register for ACPI PM Timer!\n");
                    kfree(clk);
                    return -ENOMEM;
                }
                clk->clk_dev.driver = &acpi_pm_clk_driver_mmio;
                break;
            case ACPI_GAS_ASID_PIO:
#ifdef CONFIG_PORT_IO
                clk->pio.port = fadt->x_pm_tmr_blk.address;
                clk->clk_dev.driver = &acpi_pm_clk_driver_port;
#else
                eprintk("ACPI Timer has Port I/O register but CONFIG_PORT_IO is not enabled!\n");
                kfree(clk);
                return -EINVAL;
#endif
                break;
            default:
                eprintk("Unsupported Address Space for ACPI PM Timer Generic Address\n");
                kfree(clk);
                return 0;
        }
    } else {
        printk("Using Legacy PM Timer Block in FADT\n");
#ifdef CONFIG_PORT_IO
        clk->pio.port = fadt->pm_tmr_blk;
        clk->clk_dev.driver = &acpi_pm_clk_driver_port;
#else
        eprintk("Cannot use Legacy PM Timer Block without CONFIG_PORT_IO!\n");
        kfree(clk);
        return -EINVAL;
#endif
    }

    int res;

    if(clk_source_get() == NULL) {
        printk("Setting Clock Source to ACPI PM Timer\n");
        res = clk_source_set(&clk->clk_dev);
        if(res) {
            eprintk("Failed to set clock source!\n");
            return 0; // Not necessarily a problem
        }
    }

    return 0;
}

declare_init_desc(dynamic, init_acpi_pm_timer_clk, "ACPI PM Timer Clock Source Init");

