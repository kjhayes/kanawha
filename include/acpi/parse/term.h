#ifndef __KANAWHA__ACPI_PARSE_TERM_H__
#define __KANAWHA__ACPI_PARSE_TERM_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

int
acpi_try_parse_term_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out
        );

int
acpi_try_parse_term_arg(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out
        );

int
acpi_populate_termlist(
        struct acpi_parse_ctx *ctx,
        struct acpi_termlist *list);
int
acpi_populate_arg_termlist(
        struct acpi_parse_ctx *ctx,
        struct acpi_termlist *list);

static inline int
acpi_parse_operand(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    return acpi_try_parse_term_arg(ctx, term_out);
}

#endif
