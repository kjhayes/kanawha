#ifndef __KANAWHA__ACPI_NAME_H__
#define __KANAWHA__ACPI_NAME_H__

#include <kanawha/types.h>
#include <kanawha/list.h>

struct acpi_name {
    union {
        uint8_t raw[4];
        uint32_t value;
    };
};

struct acpi_path {
    // -1  => Root Prefix
    // 0   => No Prefix
    // n>0 => 0 Number of Parent Prefixes
    int prefixes;

    size_t pathlen;
    struct acpi_name names[];
};

// prefix:
//     -1 => Absolute
//     0  => Relative
//     >0 => Number of Parent Prefixes (Think: how many ".." to prefix)
//
// Returns NULL on failure
#define ACPI_PATH_PARENT_PREFIX_ABSOLUTE (-1)
struct acpi_path *
acpi_path_create(
        size_t length,
        int prefix);

void
acpi_path_destroy(
        struct acpi_path *);

// Returns 0 on success
int
acpi_verify_name(
        struct acpi_name *name);

// Returns 0 on success
int
acpi_verify_path(
        struct acpi_path *path);

int
acpi_dump_name(
        printk_f *printer,
        struct acpi_name *name);

int
acpi_dump_path(
        printk_f *printer,
        struct acpi_path *path);

#endif
