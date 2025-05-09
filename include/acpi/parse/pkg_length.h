#ifndef __KANAWHA__ACPI_PARSE_PKG_LENGTH_H__
#define __KANAWHA__ACPI_PARSE_PKG_LENGTH_H__

#include <acpi/parse/ctx.h>

int
acpi_parse_pkg_length(
        struct acpi_parse_ctx *ctx,
        uint32_t *len_out);

int
acpi_segment_package(
        struct acpi_parse_ctx *ctx,
        struct acpi_parse_ctx *inner);

#endif
