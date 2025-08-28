
#include <acpi/interp/named_reference.h>
#include <acpi/interp/state.h>
#include <acpi/interp/name.h>
#include <acpi/interp/opcode.h>

int
acpi_interp_name_string_as_named_reference(
	struct acpi_interp_state *state,
        struct acpi_obj **obj_out)
{
    int res;

    struct acpi_path *path;
    res = acpi_interp_name_string(state, &path);
    if(res) {
	return res;
    }

    struct acpi_obj *obj;
    obj = acpi_create_named_reference(
	    acpi_interp_current_scope(state),
	    path);

    acpi_path_destroy(path);

    if(obj == NULL) {
	return -ENOMEM;
    }

    *obj_out = obj;

    return 0;
}

