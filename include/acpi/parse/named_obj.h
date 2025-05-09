#ifndef __KANAWHA__ACPI_PARSE_NAMED_OBJ_H__
#define __KANAWHA__ACPI_PARSE_NAMED_OBJ_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

int
acpi_parse_named_obj_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

#endif
