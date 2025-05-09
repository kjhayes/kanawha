#ifndef __KANAWHA__ACPI_TARGET_H__
#define __KANAWHA__ACPI_TARGET_H__

#include <kanawha/printk.h>

struct acpi_target {
    enum {
        ACPI_TARGET_NULL,
        ACPI_TARGET_DEBUG,
        ACPI_TARGET_NAME,
        ACPI_TARGET_TERM,
    } type;
    union {
        struct {
            struct acpi_path *path;
        } name;
        struct {
            struct acpi_term *term;
        } term;
    } typed_data;
};

struct acpi_target *
acpi_create_null_target(void);

struct acpi_target *
acpi_create_debug_target(void);

struct acpi_target *
acpi_create_named_target(
        struct acpi_path *path);

struct acpi_target *
acpi_create_term_target(
        struct acpi_term *term);

int
acpi_destroy_target(
        struct acpi_target *target);

int
acpi_dump_target(
        struct acpi_target *target,
        printk_f *printer,
        int depth);

#endif
