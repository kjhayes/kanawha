#ifndef __KANAWHA__ACPI_MADT_H__
#define __KANAWHA__ACPI_MADT_H__

#include <acpi/table.h>

struct acpi_madt {
    struct acpi_table_hdr hdr; 
    uint32_t lapic_address;
    uint32_t flags;
    uint8_t data[];
} __attribute__((packed));

#define ACPI_MADT_ENTRY_LAPIC  0x0
#define ACPI_MADT_ENTRY_IOAPIC 0x1
#define ACPI_MADT_ENTRY_IOAPIC_OVERRIDE 0x2
#define ACPI_MADT_ENTRY_IOAPIC_NMI 0x3
#define ACPI_MADT_ENTRY_LAPIC_NMI  0x4
#define ACPI_MADT_ENTRY_LAPIC_ADDR_OVERRIDE 0x5
#define ACPI_MADT_ENTRY_X2APIC 0x9

struct acpi_madt_entry_hdr {
    uint8_t type;
    uint8_t length;
} __attribute__((packed));

struct acpi_madt_entry_lapic {
    struct acpi_madt_entry_hdr hdr;
    uint8_t acpi_proc_id;
    uint8_t apic_id;
    uint32_t flags;
} __attribute__((packed));

struct acpi_madt_entry_ioapic {
    struct acpi_madt_entry_hdr hdr;
    uint8_t ioapic_id;
    uint8_t __resv0;
    uint32_t ioapic_addr;
    uint32_t gsi_base;
} __attribute__((packed));

struct acpi_madt_entry_ioapic_override {
    struct acpi_madt_entry_hdr hdr;
    uint8_t bus_source;
    uint8_t irq_source;
    uint32_t gsi;
    uint16_t flags;
} __attribute__((packed));

struct acpi_madt_entry_ioapic_nmi {
    struct acpi_madt_entry_hdr hdr;
    uint8_t nmi_source;
    uint8_t __resv;
    uint16_t flags;
    uint32_t gsi;
} __attribute__((packed));

struct acpi_madt_entry_lapic_nmi {
    struct acpi_madt_entry_hdr hdr;
    uint8_t acpi_proc_id;
    uint16_t flags;
    uint8_t lint;
} __attribute__((packed));

struct acpi_madt_entry_lapic_addr_override {
    struct acpi_madt_entry_hdr hdr;
    uint16_t __resv;
    uint64_t lapic_address;
} __attribute__((packed));

struct acpi_madt_entry_x2apic {
    struct acpi_madt_entry_hdr hdr;
    uint16_t __resv;
    uint32_t apic_id;
    uint32_t flags;
    uint32_t acpi_id;
} __attribute__((packed));

#endif
