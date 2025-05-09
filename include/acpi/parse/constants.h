#ifndef __KANAWHA__ACPI_PARSE_CONSTANTS_H__
#define __KANAWHA__ACPI_PARSE_CONSTANTS_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

int
acpi_parse_integer_const(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

int
acpi_parse_string_const(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

#endif
