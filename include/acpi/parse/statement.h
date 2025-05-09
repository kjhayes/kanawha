#ifndef __KANAWHA__ACPI_PARSE_STATEMENT_H__
#define __KANAWHA__ACPI_PARSE_STATEMENT_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

int
acpi_parse_statement_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

#endif
