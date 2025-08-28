#ifndef __KANAWHA__ACPI_INTERP_H__
#define __KANAWHA__ACPI_INTERP_H__

#include <kanawha/stddef.h>
#include <acpi/namespace.h>
#include <acpi/interp/state.h>

int
acpi_interpret_aml(
	struct acpi_node *scope,
	void *aml_data,
	size_t aml_len);

int acpi_interp_scope_op(struct acpi_interp_state *state);
int acpi_interp_def_op_region(struct acpi_interp_state *state);
int acpi_interp_def_field(struct acpi_interp_state *state);
int acpi_interp_def_method(struct acpi_interp_state *state);
int acpi_interp_def_device(struct acpi_interp_state *state);
int acpi_interp_def_processor(struct acpi_interp_state *state);
int acpi_interp_def_name(struct acpi_interp_state *state);
int acpi_interp_def_alias(struct acpi_interp_state *state);
int acpi_interp_def_mutex(struct acpi_interp_state *state);
int acpi_interp_def_create_bit_field(struct acpi_interp_state *state);
int acpi_interp_def_create_byte_field(struct acpi_interp_state *state);
int acpi_interp_def_create_word_field(struct acpi_interp_state *state);
int acpi_interp_def_create_dword_field(struct acpi_interp_state *state);
int acpi_interp_def_create_qword_field(struct acpi_interp_state *state);
int acpi_interp_def_create_field(struct acpi_interp_state *state);
int acpi_interp_def_thermal_zone(struct acpi_interp_state *state);
int acpi_interp_def_power_resource(struct acpi_interp_state *state);

#endif
