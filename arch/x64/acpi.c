
#include <acpi/acpi.h>
#include <acpi/madt.h>
#include <arch/x64/lapic.h>
#include <arch/x64/xapic.h>
#include <arch/x64/ioapic.h>
#include <arch/x64/cpu.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <arch/x64/vendor.h>
#include <arch/x64/cpuid.h>
#include <arch/x64/ioapic.h>
#include <arch/x64/pic.h>

static apic_id_t bsp_apic_id;

// Devices
static int
parse_madt_lapic(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_lapic *entry = (void*)hdr;
    printk("MADT APIC: id=0x%lx\n", (apic_id_t)entry->apic_id);

    struct x64_cpu *cpu = kmalloc(sizeof(struct x64_cpu));
    if(cpu == NULL) {
        return -ENOMEM;
    }
    memset(cpu, 0, sizeof(struct x64_cpu));

    int res = x64_bsp_register_smp_cpu(
            cpu,
            entry->apic_id,
            entry->apic_id == bsp_apic_id);

    if(res) {
        kfree(cpu);
        return res;
    }

    return 0;
}

static int
parse_madt_x2apic(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_x2apic *entry = (void*)hdr;
    printk("MADT X2APIC: id=0x%lx\n", (apic_id_t)entry->apic_id);

    struct x64_cpu *cpu = kmalloc(sizeof(struct x64_cpu));
    if(cpu == NULL) {
        return -ENOMEM;
    }
    memset(cpu, 0, sizeof(struct x64_cpu));
    int res = x64_bsp_register_smp_cpu(
            cpu,
            entry->apic_id,
            entry->apic_id == bsp_apic_id);

    if(res) {
        kfree(cpu);
        return res;
    }

    return 0;
}

static int
parse_madt_ioapic(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_ioapic *entry = (void*)hdr;
    printk("MADT IOAPIC: id=0x%lx, gsi_base=0x%x\n",
            (apic_id_t)entry->ioapic_id,
            entry->gsi_base);
    int res = x64_register_ioapic(
            entry->ioapic_id,
            entry->ioapic_addr,
            entry->gsi_base);
    return res;
}

// Overrides

#define ACPI_MADT_IOAPIC_OVERRIDE_BUS_ISA 0
static int
parse_madt_ioapic_override(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr,
        uint16_t *overriden_isa_irqs)
{
    int res;
    struct acpi_madt_entry_ioapic_override *entry = (void*)hdr;
    printk("MADT IOAPIC Override: bus=0x%x, ioapic-irq=0x%x, pic-irq=0x%x flags=0x%x\n",
            entry->bus_source,
            entry->gsi,
            entry->irq_source,
            entry->flags);

    int default_active_high = 0;
    int default_edge_trigger = 0;

    if(entry->bus_source == ACPI_MADT_IOAPIC_OVERRIDE_BUS_ISA)
    {
        default_active_high = 1;
        default_edge_trigger = 1;

        // IOAPIC
        irq_t ioapic_irq = x64_ioapic_irq(entry->gsi);
        if(ioapic_irq == NULL_IRQ) {
            eprintk("ACPI MADT: IOAPIC Override (Failed to get IO/APIC IRQ 0x%x)\n",
                    entry->gsi);
            return -EINVAL;
        }
        struct irq_desc *ioapic_desc = irq_to_desc(ioapic_irq);
        if(ioapic_desc == NULL) {
            eprintk("ACPI MADT: IOAPIC Override (Failed to get IO/APIC IRQ 0x%x Descriptor (global IRQ = 0x%x)\n",
                    entry->gsi, ioapic_irq);
            return -EINVAL;
        }

        // PIC
        irq_t pic_irq = x64_pic_irq(entry->irq_source);
        if(pic_irq == NULL_IRQ) {
            eprintk("ACPI MADT: IOAPIC Override (Failed to get PIC IRQ 0x%x)\n",
                    entry->gsi);
            return -EINVAL;
        }
        struct irq_desc *pic_desc = irq_to_desc(pic_irq);
        if(pic_desc == NULL) {
            eprintk("ACPI MADT: IOAPIC Override (Failed to get PIC IRQ 0x%x Descriptor (global IRQ = 0x%x)\n",
                    entry->gsi, pic_irq);
            return -EINVAL;
        }

        // Installing the Link
        struct irq_action *link =
            irq_install_direct_link(ioapic_desc, pic_desc);
        if(link == NULL) {
            eprintk("ACPI MADT: IOAPIC Override Failed to link IO/APIC IRQ 0x%x to PIC IRQ 0x%x\n",
                    entry->gsi, entry->irq_source);
            return -EINVAL;
        }

        *overriden_isa_irqs |= (1ULL<<entry->irq_source);

    } else {
        eprintk("ACPI MADT: IOAPIC Override (Unknown Bus %d)\n",
                entry->bus_source);
        return -EUNIMPL;
    }

    uint8_t polarity_flag = entry->flags & 0b11;
    uint8_t trigger_mode_flag = (entry->flags>>2) & 0b11;

    int active_high = 0;
    int edge_trigger = 0;

    switch(polarity_flag) {
        case 0b00:
            active_high = default_active_high;
            break;
        case 0b01:
            active_high = 1;
            break;
        case 0b11:
            active_high = 0;
            break;
        default:
            eprintk("Reserved polarity 0b10 in MPS INT Flags of ACPI MADT IRQ Override!\n");
            return -EINVAL;
    }

    switch(trigger_mode_flag) {
        case 0b00:
            edge_trigger = default_edge_trigger;
            break;
        case 0b01:
            edge_trigger = 1;
            break;
        case 0b11:
            edge_trigger = 0;
            break;
        default:
            eprintk("Reserved trigger_mode 0b10 in MPS INT Flags of ACPI MADT IRQ Override!\n");
            return -EINVAL;
    }

    if(active_high) {
        res = x64_ioapic_set_active_high(entry->gsi);
    } else {
        res = x64_ioapic_set_active_low(entry->gsi);
    }
    if(res) {
        return res;
    }

    if(edge_trigger) {
        res = x64_ioapic_set_edge_triggered(entry->gsi);
    } else {
        res = x64_ioapic_set_level_sensitive(entry->gsi);
    }
    if(res) {
        return res;
    }

    return 0;
}

static int
parse_madt_ioapic_nmi(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_ioapic_nmi *entry = (void*)hdr;
    printk("MADT IOAPIC NMI: gsi=0x%x\n",
            entry->gsi);
    return -EUNIMPL;
}

static int
parse_madt_lapic_nmi(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_lapic_nmi *entry = (void*)hdr;
    wprintk("MADT LAPIC NMI: lint=0x%x (Unsupported: Requires Handling ACPI Processor ID)\n",
            entry->lint);
    return 0;
}


static int
x64_parse_acpi_madt(void) {
    struct acpi_madt *madt;
    madt = (struct acpi_madt*)acpi_find_table("APIC");

    if(madt == NULL) {
        eprintk("Cannot Find ACPI MADT Table!\n");
        return -ENXIO;
    }

    uint64_t lapic_address = (uint64_t)(madt->lapic_address);

    size_t offset = sizeof(struct acpi_madt);
    struct acpi_madt_entry_hdr *hdr = (void*)madt->data;
    while(offset < madt->hdr.length)
    {
        int res = 0;
        switch(hdr->type) { 
            case ACPI_MADT_ENTRY_LAPIC_ADDR_OVERRIDE:
                lapic_address = 
                    ((struct acpi_madt_entry_lapic_addr_override*)hdr)->lapic_address;
                break;
        }
        if(res) {
            return res;
        }
        // Advance to the next entry
        offset += hdr->length;
        hdr = ((void*)hdr) + hdr->length;
    }

    printk("MADT xAPIC Physical Address = %p\n", (void*)lapic_address);
    int res = xapic_provide_mmio_base(lapic_address);
    if(res) {
        eprintk("MADT Failed to provide xAPIC physical base address! (continuing...)\n");
    }

    offset = sizeof(struct acpi_madt);
    hdr = (void*)madt->data;
    while(offset < madt->hdr.length)
    {
        int res = 0;
        switch(hdr->type) {
            case ACPI_MADT_ENTRY_LAPIC:
                res = parse_madt_lapic(madt, hdr);
                break;
            case ACPI_MADT_ENTRY_X2APIC:
                res = parse_madt_x2apic(madt, hdr);
                break;
            case ACPI_MADT_ENTRY_IOAPIC:
                res = parse_madt_ioapic(madt, hdr);
                break;

        }
        if(res) {
            return res;
        }
        // Advance to the next entry
        offset += hdr->length;
        hdr = ((void*)hdr) + hdr->length;
    }

    offset = sizeof(struct acpi_madt);
    hdr = (void*)madt->data;

    uint16_t overriden_isa_irqs = 0x0;
    while(offset < madt->hdr.length)
    {
        int res = 0;
        switch(hdr->type) {
            case ACPI_MADT_ENTRY_IOAPIC_OVERRIDE:
                res = parse_madt_ioapic_override(madt, hdr, &overriden_isa_irqs);
                break;
            case ACPI_MADT_ENTRY_IOAPIC_NMI:
                res = parse_madt_ioapic_nmi(madt, hdr);
                break;
            case ACPI_MADT_ENTRY_LAPIC_NMI:
                res = parse_madt_lapic_nmi(madt, hdr);
                break;
        }
        if(res) {
            return res;
        }

        offset += hdr->length;
        hdr = ((void*)hdr) + hdr->length;
    }

    for(size_t i = 0; i < 16; i++) {
        // This ISA IRQ has already been mapped by an override entry
        if((overriden_isa_irqs >> i) & 1) {
            printk("ISA IRQ 0x%x was overriden\n", i);
            continue;
        }

        // This ISA IRQ didn't have an override, identity map it
        irq_t pic_irq = x64_pic_irq((hwirq_t)i);
        struct irq_desc *pic_desc;
        if(pic_irq == NULL_IRQ) {
            pic_desc = NULL;
        } else {
            pic_desc = irq_to_desc(pic_irq);
        }
        if(pic_desc == NULL) {
            wprintk("Failed to identity map PIC IRQ 0x%x to the IO/APIC (failed to get PIC IRQ)!\n",
                    (u_t)i);
            continue;
        }

        irq_t ioapic_irq = x64_ioapic_irq((hwirq_t)i);
        struct irq_desc *ioapic_desc;
        if(ioapic_irq == NULL_IRQ) {
            ioapic_desc = NULL;
        } else {
            ioapic_desc = irq_to_desc(ioapic_irq);
        }
        if(ioapic_desc == NULL) {
            wprintk("Failed to identity map PIC IRQ 0x%x to the IO/APIC (failed to get IO/APIC IRQ)!\n",
                    (u_t)i);
            continue;
        }

        struct irq_action *link = irq_install_direct_link(ioapic_desc, pic_desc);
        if(link == NULL) {
            wprintk("Failed to created link from PIC IRQ 0x%x to IO/APIC IRQ 0x%x\n",
                    (u_t)i, (u_t)i);
            continue;
        }

        printk("Linked ISA 0x%x to IOAPIC 0x%x\n",
                i, i);
    }

    return 0;
}
declare_init_desc(topo, x64_parse_acpi_madt, "Parsing ACPI MADT");

static int 
current_apic_id_from_cpuid(apic_id_t *id)
{
    int res;
    x64_vendor_t vendor = x64_get_vendor();

    struct x64_cpuid_result result;

    switch(vendor) {
        case X64_VENDOR_AMD:
            x64_cpuid(0x80000001, &result);
            if(result.ecx & (1UL<<22)) { // Checking for extended topology support in ECX
                x64_cpuid(0x8000001E, &result); // Getting the extended APIC ID
                *id = result.eax;
                res = 0;
                break;
            } else {
                x64_cpuid(0x1, &result);
                *id = (uint8_t)(result.ebx >> 24);
                res = 0;
                break;
            }
        case X64_VENDOR_INTEL:
            x64_cpuid(0xB, &result);
            *id = result.edx; // EDX contains the extended APIC ID
                           // (lower 8-bits equivalent to xAPIC id if x2apic isn't supported)
            res = 0;
            break;
        default:
            eprintk("Do not know how to get APICID using CPUID with vendor \"%s\"\n",
                    x64_vendor_string(vendor));
            res = -EUNIMPL;
            break;
    }
    return res;
}

static int
x64_cache_bsp_apic_id(void) {
    return current_apic_id_from_cpuid(&bsp_apic_id);
}

declare_init_desc(static, x64_cache_bsp_apic_id, "Reading BSP APIC ID From CPUID");

