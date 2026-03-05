#ifndef __KANAWHA__ACPI_INTERP_STRING_H__
#define __KANAWHA__ACPI_INTERP_STRING_H__

#include <acpi/interp/state.h>
#include <acpi/object.h>

int
acpi_interp_string_after_opcode(struct acpi_interp_state *state,
                                struct acpi_obj **str);

int
acpi_interp_string(struct acpi_interp_state *state, struct acpi_obj **str);

#endif
