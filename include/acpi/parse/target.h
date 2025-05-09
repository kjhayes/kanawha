#ifndef __KANAWHA__ACPI_PARSE_TARGET_H__
#define __KANAWHA__ACPI_PARSE_TARGET_H__

#include <acpi/parse/ctx.h>
#include <acpi/target.h>

int
acpi_parse_target(
        struct acpi_parse_ctx *ctx,
        struct acpi_target **target_out);

#endif
