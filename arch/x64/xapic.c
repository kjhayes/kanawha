
#include <kanawha/stddef.h>
#include <kanawha/stdint.h>
#include <kanawha/mmio.h>
#include <arch/x64/lapic.h>
#include <arch/x64/xapic.h>
#include <arch/x64/cpu.h>

#define XAPIC_MMIO_SIZE 0x1000

static struct lapic_ops xapic_ops;

static int xapic_phys_base_valid = 0;
static paddr_t xapic_phys_base = 0;
static void __mmio *xapic_mmio_base = NULL;

int
xapic_provide_mmio_base(paddr_t base)
{
    if(xapic_phys_base_valid) {
        if(xapic_phys_base == base) {
            // Redundant info is fine
            return 0;
        } else {
            eprintk("xAPIC provided conflicting values for MMIO Base! (first=%p, second=%p)\n",
                    xapic_phys_base, base);
            return -EEXIST;
        }
    } else {
        xapic_phys_base_valid = 1;
        xapic_phys_base = base;
        return 0;
    }
}

// Set up xAPIC mmio mapping if needed
static int
xapic_setup_mmio(void) {
    if(!xapic_phys_base_valid) {
        eprintk("Reached xAPIC MMIO initialization without a valid xAPIC MMIO address!\n");
        return -EINVAL;
    }

    if(xapic_mmio_base != NULL) {
        // We've already mapped the region
        return 0;
    }

    xapic_mmio_base = mmio_map(xapic_phys_base, XAPIC_MMIO_SIZE);
    if(xapic_mmio_base == NULL) {
        return -EINVAL;
    }
    return 0;
}

int
xapic_setup_lapic(struct lapic *apic)
{
    int res;

    apic->ops = &xapic_ops;

    res = xapic_setup_mmio();
    if(res) {
        return res;
    }

    return 0;
}

static uint64_t
xapic_read_reg(
        struct lapic *apic,
        size_t reg)
{
    dprintk("xapic_read_reg(apic=%p, reg=0x%lx, mmio_base=%p)\n",
            apic, reg, xapic_mmio_base);
    return (uint64_t)mmio_readl(xapic_mmio_base + reg);
}

static int
xapic_write_reg(
        struct lapic *apic,
        size_t reg,
        uint64_t val)
{
    dprintk("xapic_write_reg(apic=%p, reg=0x%lx, mmio_base=%p, value=0x%llx)\n",
            apic, reg, xapic_mmio_base, (unsigned long long)val);
    mmio_writel(xapic_mmio_base + reg, (uint32_t)val);
    return 0;
}

static apic_id_t
xapic_read_id(
        struct lapic *apic)
{
    return (uint32_t)mmio_readl(xapic_mmio_base + LAPIC_REG_ID) >> 24;
}

static int
xapic_send_ipi(
        struct lapic *apic,
        apic_id_t target,
        uint8_t vector,
        int message_type,
        int logical,
        int assert,
        int trigger_mode)
{
    uint32_t icr_low =
        vector |
        ((uint32_t)message_type << 8) |
        ((uint32_t)!!logical << 11) |
        ((uint32_t)!!assert << 14) |
        ((uint32_t)!!trigger_mode << 15);

    uint32_t icr_high = target << 24;

    lapic_write_reg(apic, LAPIC_REG_ICR_HIGH, icr_high);
    lapic_write_reg(apic, LAPIC_REG_ICR_LOW, icr_low);


    // Wait for the IPI to be delivered
    do {
        icr_low = lapic_read_reg(apic, LAPIC_REG_ICR_LOW);
    } while(icr_low & (1ULL<<12)); // ICR pending bit

    return 0;
}


static struct lapic_ops xapic_ops = {
    .read_reg = xapic_read_reg,
    .write_reg = xapic_write_reg,
    .read_id = xapic_read_id,
    .send_ipi = xapic_send_ipi,
};

