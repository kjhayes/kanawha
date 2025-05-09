#ifndef __KANAWHA__ACPI_PARSE_ARITH_OP_H__
#define __KANAWHA__ACPI_PARSE_ARITH_OP_H__

#include <acpi/parse/ctx.h>
#include <acpi/term.h>

int
acpi_parse_arith_op_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out);

#endif
