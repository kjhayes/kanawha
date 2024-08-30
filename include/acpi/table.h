#ifndef __KANAWHA__ACPI_TABLE_H__
#define __KANAWHA__ACPI_TABLE_H__

#include <kanawha/stdint.h>

struct acpi_rsdp {
    uint8_t signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_ptr;
} __attribute__((packed));

struct acpi_xsdp {
    uint8_t signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_ptr;
    uint32_t length;
    uint64_t xsdt_ptr;
    uint8_t ext_checksum;
    uint8_t reserved[3];
} __attribute__((packed));

struct acpi_table_hdr {
    uint8_t signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t createor_revision;
} __attribute__((packed));

struct acpi_rsdt {
    struct acpi_table_hdr hdr;
    uint32_t table_ptrs[];
} __attribute__((packed));

struct acpi_xsdt {
    struct acpi_table_hdr hdr;
    uint64_t table_ptrs[];
} __attribute__((packed));

#endif
