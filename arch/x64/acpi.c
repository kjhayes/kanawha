
#include <acpi/acpi.h>
#include <acpi/madt.h>
#include <arch/x64/lapic.h>
#include <arch/x64/xapic.h>
#include <arch/x64/cpu.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <arch/x64/vendor.h>
#include <arch/x64/cpuid.h>

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
    printk("MADT IOAPIC: id=0x%lx\n", (apic_id_t)entry->ioapic_id);
    return 0;
}

// Overrides
static int
parse_madt_ioapic_override(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_ioapic_override *entry = (void*)hdr;
    return 0;
}

static int
parse_madt_ioapic_nmi(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_ioapic_nmi *entry = (void*)hdr;
    return 0;
}

static int
parse_madt_lapic_nmi(
        struct acpi_madt *madt,
        struct acpi_madt_entry_hdr *hdr)
{
    struct acpi_madt_entry_lapic_nmi *entry = (void*)hdr;
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
    while(offset < madt->hdr.length)
    {
        int res = 0;
        switch(hdr->type) {
            case ACPI_MADT_ENTRY_IOAPIC_OVERRIDE:
                res = parse_madt_ioapic_override(madt, hdr);
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

