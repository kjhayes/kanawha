
#include <acpi/interp/state.h>
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/term_arg.h>
#include <acpi/namespace.h>
#include <kanawha/errno.h>

int
acpi_interp_def_op_region(
	struct acpi_interp_state *state)
{
    int res;

    struct acpi_path *name_string;
    res = acpi_interp_name_string(state, &name_string);
    if(res) {
	wprintk("acpi_interp_def_op_region: Malformed name string!\n");
	return res;
    }

    uint8_t region_space;
    res = acpi_interp_raw_u8(state, &region_space);
    if(res) {
	wprintk("acpi_interp_def_op_region: Malformed region_space!\n");
        acpi_path_destroy(name_string);
	return res;
    }

    unsigned long region_offset;
    res = acpi_interp_term_arg_to_integer(state, &region_offset);
    if(res) {
	wprintk("acpi_interp_def_op_region: Malformed region_offset!\n");
        acpi_path_destroy(name_string);
	return res;
    }

    unsigned long region_len;
    res = acpi_interp_term_arg_to_integer(state, &region_len);
    if(res) {
	wprintk("acpi_interp_def_op_region: Malformed region_len!\n");
        acpi_path_destroy(name_string);
	return res;
    }

    struct acpi_obj *op_region =
	acpi_create_op_region_obj(
		region_space,
		region_offset,
		region_len);
    if(op_region == NULL) {
	wprintk("acpi_interp_def_op_region: Failed to create op_region object!\n");
        acpi_path_destroy(name_string);
	return -ENOMEM;
    }

    res = acpi_node_create_named_object(
	    acpi_interp_current_scope(state),
	    name_string,
	    op_region);
    if(res) {
	wprintk("acpi_interp_def_op_region: Failed to create op_region object!\n");
        acpi_path_destroy(name_string);
	acpi_obj_put(op_region);
	return res;
    }

    acpi_path_destroy(name_string);
    acpi_obj_put(op_region);
    return 0;
}

