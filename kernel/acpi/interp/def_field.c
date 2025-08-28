
#include <acpi/interp/state.h>
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/term_arg.h>
#include <acpi/namespace.h>
#include <acpi/name.h>
#include <kanawha/errno.h>

int
acpi_interp_def_field(
	struct acpi_interp_state *state)
{
    int res;

    size_t base_rip = state->frame->rip;

    ssize_t pkglength = acpi_interp_pkglength(state);
    if(pkglength < 0) {
	return pkglength;
    }

    size_t target_rip = base_rip + pkglength;
    if(target_rip > state->frame->aml_len) {
	wprintk("acpi_interp_def_field: pkglength extends beyond current frame!\n");
	return -EINVAL;
    }

    struct acpi_path *op_region_path;
    res = acpi_interp_name_string(state, &op_region_path);
    if(res) {
	return res;
    }

    struct acpi_obj *op_region =
	acpi_interp_get_named_object(
		state,
		op_region_path);
    if(op_region == NULL) {
	wprintk("acpi_interp_def_field: Failed to find named op region at path \"");
	acpi_dump_path(do_printk, op_region_path);
	do_printk("\"\n");
        acpi_path_destroy(op_region_path);
	return -ENXIO;
    }

    if(acpi_obj_get_type(op_region) != ACPI_OBJ_TYPE_OP_REGION) {
	wprintk("acpi_interp_def_field: Object at path \"");
	acpi_dump_path(do_printk, op_region_path);
	do_printk("\" is a %s, expected %s\n",
		acpi_obj_type_to_string(acpi_obj_get_type(op_region)),
		acpi_obj_type_to_string(ACPI_OBJ_TYPE_OP_REGION));
        acpi_path_destroy(op_region_path);
	acpi_obj_put(op_region);
	return -EINVAL;
    }

    acpi_path_destroy(op_region_path);

    uint8_t base_flags_byte;
    res = acpi_interp_raw_u8(state, &base_flags_byte);
    if(res) {
	wprintk("acpi_interp_def_field: Failed to read flags byte!\n");
	return res;
    }

    acpi_field_unit_access_t access;
    switch(base_flags_byte & 0xF) {
	case 0: access = ACPI_FIELD_UNIT_ACCESS_ANY;    break;
	case 1: access = ACPI_FIELD_UNIT_ACCESS_BYTE;   break;
	case 2: access = ACPI_FIELD_UNIT_ACCESS_WORD;   break;
	case 3: access = ACPI_FIELD_UNIT_ACCESS_DWORD;  break;
	case 4: access = ACPI_FIELD_UNIT_ACCESS_QWORD;  break;
	case 5: access = ACPI_FIELD_UNIT_ACCESS_BUFFER; break;
	default:
            acpi_obj_put(op_region);
	    wprintk("acpi_interp_def_field: Invalid access type 0x%x\n",
		    (u_t)((base_flags_byte) & 0xF));
	    return -EINVAL;
    }
    acpi_field_unit_update_rule_t update_rule;
    switch((base_flags_byte >> 5) & 0b11) {
	case 0: update_rule = ACPI_FIELD_UNIT_UPDATE_RULE_PRESERVE;    break;
	case 1: update_rule = ACPI_FIELD_UNIT_UPDATE_RULE_WRITE_ONES;  break;
	case 2: update_rule = ACPI_FIELD_UNIT_UPDATE_RULE_WRITE_ZEROS; break;
	default:
            acpi_obj_put(op_region);
	    wprintk("acpi_interp_def_field: Invalid update_rule 0x%x\n",
		    (u_t)((base_flags_byte>>5) & 0b11));
	    return -EINVAL;
    }
    unsigned int locked = (base_flags_byte >> 4) & 0b1;

    size_t cur_bitoffset = 0;

    struct acpi_path *tmp_path = acpi_path_create(1, ACPI_PATH_PREFIX_NONE);
    if(tmp_path == NULL) {
        acpi_obj_put(op_region);
        return -ENOMEM;
    }

    ssize_t tmp_pkglength;
    struct acpi_obj *tmp_obj;

    while(state->frame->rip < target_rip) {
	ssize_t room_left = target_rip - state->frame->rip;
	
	uint8_t first_byte;
	res = acpi_interp_peek_raw_u8(state, &first_byte);
	if(res) {
            acpi_obj_put(op_region);
	    return res;
	}

	switch(first_byte) {
	    case 0x00: // Reserved field
		acpi_interp_advance_frame(state, 1);
		tmp_pkglength = acpi_interp_pkglength(state);
		if(tmp_pkglength < 0) {
		    wprintk("acpi_interp_def_field: Failed to read pkglength of a reserved field unit!\n");
		    acpi_path_destroy(tmp_path);
		    acpi_obj_put(op_region);
		    return -EINVAL;
		}
		cur_bitoffset += tmp_pkglength;
		break;
	    case 0x01: // AccessField
		wprintk("acpi_interp_def_field: encountered AccessField (UNIMPL)\n");
		acpi_path_destroy(tmp_path);
		acpi_obj_put(op_region);
		return -EUNIMPL;
	    case 0x02: // ConnectField
		wprintk("acpi_interp_def_field: encountered ConnectField (UNIMPL)\n");
		acpi_path_destroy(tmp_path);
		acpi_obj_put(op_region);
		return -EUNIMPL;
	    case 0x03: // ExtendedAccessField
		wprintk("acpi_interp_def_field: encountered ExtendedAccessField (UNIMPL)\n");
		acpi_path_destroy(tmp_path);
		acpi_obj_put(op_region);
		return -EUNIMPL;
	    default: // NamedField
		res = acpi_interp_name_segment(state, &tmp_path->names[0]);
		if(res) {
		    wprintk("acpi_interp_def_field: Failed to get FieldUnit name!\n");
		    acpi_path_destroy(tmp_path);
		    acpi_obj_put(op_region);
		    return res;
		}
		tmp_pkglength = acpi_interp_pkglength(state);
                if(tmp_pkglength < 0) {
		    wprintk("acpi_interp_def_field: Failed to get FieldUnit length!\n");
		    acpi_path_destroy(tmp_path);
		    acpi_obj_put(op_region);
		    return res;
		}

		tmp_obj = acpi_create_field_unit_obj(
			op_region,
			tmp_pkglength,
			cur_bitoffset,
			access,
			update_rule,
			locked);
		if(tmp_obj == NULL) {
		    wprintk("acpi_interp_def_field: Failed to create FieldUnit object!\n");
		    acpi_path_destroy(tmp_path);
		    acpi_obj_put(op_region);
		    return res;
		}

		res = acpi_interp_create_named_object(
			state,
			tmp_path,
			tmp_obj);
		if(res) {
		    wprintk("acpi_interp_def_field: Failed to add FieldUnit object to namespace!\n");
                    acpi_path_destroy(tmp_path);
		    acpi_obj_put(op_region);
		    acpi_obj_put(tmp_obj);
		    return res;
		}

		acpi_obj_put(tmp_obj);
		cur_bitoffset += tmp_pkglength;
		break;
	}
    }

    acpi_path_destroy(tmp_path);
    acpi_obj_put(op_region);

    if(state->frame->rip != target_rip) {
	wprintk("acpi_interp_def_field: pkglength is incorrect!\n");
	return -EINVAL;
    }

    return 0;
}

