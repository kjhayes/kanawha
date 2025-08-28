#ifndef __KANAWHA__ACPI_PARSE_PKGLENGTH_H__
#define __KANAWHA__ACPI_PARSE_PKGLENGTH_H__

#include <acpi/interp/state.h>

ssize_t
acpi_interp_pkglength(
        struct acpi_interp_state *state);

int
acpi_interp_push_pkg_frame(
	struct acpi_interp_state *state);

#endif
