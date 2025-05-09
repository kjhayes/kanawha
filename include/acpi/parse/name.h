#ifndef __KANAWHA__ACPI_PARSE_NAME_H__
#define __KANAWHA__ACPI_PARSE_NAME_H__

#include <acpi/parse/ctx.h>
#include <acpi/name.h>

int
acpi_parse_name_segment(
        struct acpi_parse_ctx *ctx,
        struct acpi_name *name_out);

int
acpi_parse_name_string(
        struct acpi_parse_ctx *ctx,
        struct acpi_path **path_out);

#endif
