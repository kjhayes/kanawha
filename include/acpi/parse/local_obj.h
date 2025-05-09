#ifndef __KANAWHA__ACPI_PARSE_LOCAL_OBJ_H__
#define __KANAWHA__ACPI_PARSE_LOCAL_OBJ_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

int
acpi_parse_arg_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

int
acpi_parse_local_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

#endif
