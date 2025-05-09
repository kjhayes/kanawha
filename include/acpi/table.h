#ifndef __KANAWHA__ACPI_TABLE_H__
#define __KANAWHA__ACPI_TABLE_H__

#include <kanawha/types.h>
#ifdef CONFIG_ACPI_SYSFS
#include <kanawha/list.h>
#include <kanawha/fs/sys/vfs.h>
#endif

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
    uint32_t creator_revision;
} __attribute__((packed));

struct acpi_table_data {
    struct acpi_table_hdr hdr;
    uint8_t data[];
};

struct acpi_table {
    struct stree_node tree_node;
    char signature_str[5];

#ifdef CONFIG_ACPI_SYSFS
    ilist_node_t sysfs_temp_list_node; // This is an ugly HACK
                                       // to allow registering tables 
                                       // well before any sysfs can be
                                       // initialized
    struct vfs_node sysfs_node;
#endif

    unsigned long flags;
    struct acpi_table_hdr *table;
};

#endif
