#ifndef __KANAWHA__ACPI_PARSE_DATA_OBJ_H__
#define __KANAWHA__ACPI_PARSE_DATA_OBJ_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

int
acpi_try_parse_data_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

int
acpi_try_parse_computational_data(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

#endif
