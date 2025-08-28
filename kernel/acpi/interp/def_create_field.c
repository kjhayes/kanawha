
#include <acpi/interp.h>
#include <acpi/object.h>
#include <acpi/interp/state.h>
#include <acpi/interp/term_arg.h>
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>

static int
acpi_interp_create_field_generic(
	struct acpi_interp_state *state,
	unsigned long bitwidth,
	unsigned long bits_per_index)
{
    int res;
    struct acpi_obj *buffer;
    res = acpi_interp_term_arg(state, &buffer);
    if(res) {
	wprintk("acpi_interp_create_field_generic: Failed to get resolve buffer\n");
	return res;
    }

    if(acpi_obj_get_type(buffer) != ACPI_OBJ_TYPE_BUFFER) {
	acpi_obj_put(buffer);
	return -EINVAL;
    }

    unsigned long index;
    res = acpi_interp_term_arg_to_integer(
	    state,
	    &index);
    if(res) {
	wprintk("acpi_interp_create_field_generic: Failed to get resolve index\n");
	acpi_obj_put(buffer);
	return res;
    }

    if(bitwidth == 0) {
	res = acpi_interp_term_arg_to_integer(state, &bitwidth);
	if(res) {
	    wprintk("acpi_interp_create_field_generic: Failed to get resolve bitwidth\n");
	    acpi_obj_put(buffer);
	    return res;
	}
    }

    if(bitwidth == 0) {
	acpi_obj_put(buffer);
	return -EINVAL;
    }

    size_t bitoffset = index * bits_per_index;

    struct acpi_obj *field;
    field = acpi_create_buffer_field_obj(
	        buffer,
	        bitoffset,
	        bitwidth);
    acpi_obj_put(buffer);
    if(field == NULL) {
	return -ENOMEM;
    }

    struct acpi_path *name_string;
    res = acpi_interp_name_string(
	    state,
	    &name_string);
    if(res) {
	acpi_obj_put(field);
	return res;
    }

    res = acpi_interp_create_named_object(
	    state,
	    name_string,
	    field);
    acpi_obj_put(field);
    acpi_path_destroy(name_string);
    if(res) {
	return res;
    }

    return 0;
}

int
acpi_interp_def_create_bit_field(
	struct acpi_interp_state *state)
{
    return acpi_interp_create_field_generic(state, 1, 1);
}
int
acpi_interp_def_create_byte_field(
	struct acpi_interp_state *state)
{
    return acpi_interp_create_field_generic(state, 8, 8);
}
int
acpi_interp_def_create_word_field(
	struct acpi_interp_state *state)
{
    return acpi_interp_create_field_generic(state, 16, 8);
}
int
acpi_interp_def_create_dword_field(
	struct acpi_interp_state *state)
{
    return acpi_interp_create_field_generic(state, 32, 8);
}
int
acpi_interp_def_create_qword_field(
	struct acpi_interp_state *state)
{
    return acpi_interp_create_field_generic(state, 64, 8);
}
int
acpi_interp_def_create_field(
	struct acpi_interp_state *state)
{
    return acpi_interp_create_field_generic(state, 0, 1);
}

