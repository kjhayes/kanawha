#ifndef __KANAWHA__ACPI_PARSE_OP_REGION_H__
#define __KANAWHA__ACPI_PARSE_OP_REGION_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

struct acpi_term *
acpi_parse_def_op_region(
        struct acpi_parse_ctx *ctx);

struct acpi_term *
acpi_parse_def_op_region_fields(
        struct acpi_parse_ctx *ctx);
 
#endif
