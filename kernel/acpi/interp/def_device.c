
#include <acpi/interp/state.h>
#include <acpi/interp/name.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/namespace.h>
#include <acpi/object.h>
#include <kanawha/errno.h>

int
acpi_interp_def_device(
	struct acpi_interp_state *state)
{
    int res;

    size_t base_rip = state->frame->rip;

    ssize_t pkglength = acpi_interp_pkglength(state);
    if(pkglength < 0) {
	return pkglength;
    }

    struct acpi_path *path;
    res = acpi_interp_name_string(state, &path);
    if(res) {
	return res;
    }

    struct acpi_obj *device_obj = acpi_create_device_obj();
    if(device_obj == NULL) {
	acpi_path_destroy(path);
	return -ENOMEM;
    }

    res = acpi_interp_create_named_object(
	    state,
	    path,
	    device_obj);
    if(res) {
        acpi_obj_put(device_obj);
        acpi_path_destroy(path);
	return res;
    }

    acpi_obj_put(device_obj);

    ssize_t term_len = pkglength - (state->frame->rip - base_rip);
    if(term_len < 0) {
	acpi_path_destroy(path);
	return -EINVAL;
    }

    struct acpi_node *scope = acpi_interp_lookup(state, path);
    acpi_path_destroy(path);
    if(scope == NULL) {
	return -EINVAL;
    }

    res = acpi_interp_push_inner_frame(
	    state,
	    scope,
	    state->frame->rip,
	    term_len,
	    ACPI_INTERP_PUSH_FRAME_LOCAL);
    acpi_node_put(scope);
    if(res) {
	return res;
    }

    acpi_interp_advance_frame(state, term_len);

    return 0;
}

