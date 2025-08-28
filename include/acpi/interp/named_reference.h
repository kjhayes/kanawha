#ifndef __KANAWHA__ACPI_INTERP_NAMED_REFERENCE_H__
#define __KANAWHA__ACPI_INTERP_NAMED_REFERENCE_H__

#include <acpi/name.h>
#include <acpi/interp/state.h>
#include <acpi/interp/opcode.h>

int
acpi_interp_name_string_as_named_reference(
	struct acpi_interp_state *state,
        struct acpi_obj **obj_out);

#endif
