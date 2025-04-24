#ifndef __KANAWHA__ACPI_ACPI_H__
#define __KANAWHA__ACPI_ACPI_H__

#include <acpi/table.h>

#ifdef CONFIG_ACPI_SYSFS
#include <kanawha/list.h>
#include <kanawha/fs/sys/vfs.h>
#endif


int
acpi_provide_rsdp(struct acpi_rsdp *rsdp);
int
acpi_provide_xsdp(struct acpi_xsdp *xsdp);

struct acpi_table_hdr *
acpi_find_table(const char *signature);

uint32_t acpi_revision(void);

struct acpi_table_ptr {
    struct acpi_table_hdr *table;
    struct stree_node tree_node;
    char signature_str[5];

#ifdef CONFIG_ACPI_SYSFS
    ilist_node_t sysfs_temp_list_node; // This is an ugly HACK
                                       // to allow registering tables 
                                       // well before any sysfs can be
                                       // initialized
    struct vfs_node sysfs_node;
#endif
};

#endif
