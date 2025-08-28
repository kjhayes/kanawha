#ifndef __KANAWHA__ACPI_INTERP_TERM_ARG_H__
#define __KANAWHA__ACPI_INTERP_TERM_ARG_H__

#include <acpi/interp/state.h>
#include <acpi/object.h>

int
acpi_interp_term_arg(
	struct acpi_interp_state *state,
	struct acpi_obj **obj);

// Helper Functions
int
acpi_interp_term_arg_to_integer(
	struct acpi_interp_state *state,
	unsigned long *value);

//
int acpi_interp_def_buffer(
	struct acpi_interp_state *state,
	struct acpi_obj **obj_out);
int acpi_interp_def_package(
	struct acpi_interp_state *state,
	struct acpi_obj **obj_out);
int acpi_interp_def_varpackage(
	struct acpi_interp_state *state,
	struct acpi_obj **obj_out);
//

#endif
