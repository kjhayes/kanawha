
#include <acpi/interp/namespace.h>
#include <acpi/name.h>

struct acpi_node *
acpi_interp_lookup(
	struct acpi_interp_state *state,
	struct acpi_path *path)
{
    DEBUG_ASSERT(KERNEL_ADDR(state->frame));

    struct acpi_node *scope = state->frame->scope;

    return acpi_node_lookup(scope, path);
}

int
acpi_interp_create_named_object(
	struct acpi_interp_state *state,
	struct acpi_path *path,
	struct acpi_obj *object)
{
    return acpi_node_create_named_object(
	    acpi_interp_current_scope(state),
	    path,
	    object);
}

struct acpi_obj *
acpi_interp_get_named_object(
	struct acpi_interp_state *state,
	struct acpi_path *path)
{
    struct acpi_obj *obj =
	acpi_node_get_named_object(
	    acpi_interp_current_scope(state),
	    path);
    if(obj == NULL) {
	return NULL;
    }
    return obj;
}
