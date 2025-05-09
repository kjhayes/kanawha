#ifndef __KANAWHA__ACPI_TERMS_OP_REGION_H__
#define __KANAWHA__ACPI_TERMS_OP_REGION_H__

#include <kanawha/types.h>
#include <acpi/term.h>
#include <acpi/name.h>

struct acpi_op_region_field_list {
    ilist_t field_list;
};

struct acpi_op_region_field_flags
{
    enum acpi_op_region_field_access_type {
        ACPI_OP_REGION_FIELD_ACCESS_TYPE_ANY,
        ACPI_OP_REGION_FIELD_ACCESS_TYPE_BYTE,
        ACPI_OP_REGION_FIELD_ACCESS_TYPE_WORD,
        ACPI_OP_REGION_FIELD_ACCESS_TYPE_DWORD,
        ACPI_OP_REGION_FIELD_ACCESS_TYPE_QWORD,
        ACPI_OP_REGION_FIELD_ACCESS_TYPE_BUFFER,
        ACPI_OP_REGION_FIELD_ACCESS_TYPE_RESERVED,
    } access_type;

    enum acpi_op_region_update_rule {
        ACPI_OP_REGION_FIELD_UPDATE_PRESERVE,
        ACPI_OP_REGION_FIELD_UPDATE_WRITE_AS_ONES,
        ACPI_OP_REGION_FIELD_UPDATE_WRITE_AS_ZEROS,
        ACPI_OP_REGION_FIELD_UPDATE_RESERVED,
    } update_rule;

    unsigned locked : 1;
};

struct acpi_op_region_field
{
    ilist_node_t list_node;

    struct acpi_op_region_field_flags flags;

    struct acpi_name name;

    size_t offset;
    size_t length;
};

struct acpi_term *
acpi_create_op_region_term(
        struct acpi_path *path,
        uint8_t region_space,
        struct acpi_term *offset_term,
        struct acpi_term *length_term);

struct acpi_term *
acpi_create_op_region_fields_term(
        struct acpi_path *path,
        struct acpi_op_region_field_list *list);

struct acpi_op_region_field *
acpi_create_blank_op_region_field(void);
int
acpi_destroy_op_region_field(
        struct acpi_op_region_field *field);

struct acpi_op_region_field_list *
acpi_create_empty_op_region_field_list(void);
int
acpi_destroy_op_region_field_list(
        struct acpi_op_region_field_list *list);
int
acpi_op_region_field_list_append(
        struct acpi_op_region_field_list *list,
        struct acpi_op_region_field *field);

#endif
