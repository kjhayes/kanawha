#ifndef __KANAWHA__ACPI_INTERP_NAMESPACE_H__
#define __KANAWHA__ACPI_INTERP_NAMESPACE_H__

#include <acpi/namespace.h>
#include <acpi/interp/state.h>

struct acpi_node *
acpi_interp_lookup(
	struct acpi_interp_state *state,
	struct acpi_path *path);

int
acpi_interp_create_named_object(
	struct acpi_interp_state *state,
	struct acpi_path *path,
	struct acpi_obj *object);

struct acpi_obj *
acpi_interp_get_named_object(
	struct acpi_interp_state *state,
	struct acpi_path *path);

#endif
