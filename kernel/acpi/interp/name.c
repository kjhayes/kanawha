
#include <acpi/name.h>
#include <acpi/interp/opcode.h>
#include <acpi/interp/state.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/opcode.h>

#include <kanawha/errno.h>

int
acpi_interp_name_segment(
	struct acpi_interp_state *state,
        struct acpi_name *name)
{
    int res;

    res = acpi_interp_raw_u32(state, &name->value);
    if(res) {
	wprintk("acpi_interp_name_segment: Failed to read segment data!\n");
        return res;
    }

    res = acpi_verify_name(name);
    if(res) {
	wprintk("acpi_interp_name_segment: name segment is not valid (");
	acpi_dump_name(do_printk, name);
	do_printk(")! (err=%s)\n",
		errnostr(res)
		);
        return res;
    }

    return 0;
}

int
acpi_interp_name_string(
	struct acpi_interp_state *state,
        struct acpi_path **path_out)
{
    int res;

    int prefix = 0;

    uint8_t byte;
    res = acpi_interp_peek_raw_u8(state, &byte);
    if(res) {
	wprintk("acpi_interp_name_string: Failed to read first byte!\n");
        return res;
    }

    int num_ancestors = 0;

    // Determine Prefixes
    switch(byte) {
        case AML_ROOT_CHAR:
            prefix = ACPI_PATH_PREFIX_ROOT;
	    acpi_interp_advance_frame(state, 1);
            break;
        case AML_PARENT_PREFIX_OP:
	    num_ancestors = 0;
            while(1) {
                num_ancestors++;
		acpi_interp_advance_frame(state, 1);
                res = acpi_interp_peek_raw_u8(state, &byte);
                if(res) {
	            wprintk("acpi_interp_name_string: Failed to peek byte after parent prefix!\n");
                    return res;
                }
                if(byte != AML_PARENT_PREFIX_OP) {
                    break;
                }
            }
	    prefix = ACPI_PATH_PREFIX_ANCESTOR(num_ancestors);
            break;
        default:
	    prefix = ACPI_PATH_PREFIX_NONE;
            break;
    }

    size_t pathlen = 1;

    res = acpi_interp_peek_raw_u8(state, &byte);
    if(res) {
	wprintk("acpi_interp_name_string: Failed to peek first non-prefix byte!\n");
        return res;
    }

    switch(byte) {
        case 0x00:
            pathlen = 0;
	    acpi_interp_advance_frame(state, 1);
            break;
        case AML_DUAL_NAME_PREFIX:
            pathlen = 2;
	    acpi_interp_advance_frame(state, 1);
            break;
        case AML_MULTI_NAME_PREFIX:
	    acpi_interp_advance_frame(state, 1);
            res = acpi_interp_raw_u8(state, &byte);
	    if(res) {
	        wprintk("acpi_interp_name_string: Failed to read MULTI_NAME_PREFIX length!\n");
		return res;
	    }
            pathlen = byte;
            break;
        default:
            break;
    }

    struct acpi_path *path = acpi_path_create(pathlen, prefix);
    if(path == NULL) {
	wprintk("acpi_interp_name_string: Failed to allocate acpi_path!\n");
        return -ENOMEM;
    }

    for(size_t i = 0; i < pathlen; i++) {
        struct acpi_name *name = &path->names[i];
        res = acpi_interp_name_segment(state, name);
        if(res) {
	    wprintk("acpi_interp_name_string: Failed to read name segment!\n");
	    acpi_path_destroy(path);
            return res;
        }
    }

    if(path_out != NULL) {
        *path_out = path;
    } else {
        acpi_path_destroy(path);
    }

    return 0;
}

int
acpi_opcode_is_name_string(
	aml_opcode_t opcode)
{
    switch(opcode) {
	case AML_NAME_CHAR_A:
	case AML_NAME_CHAR_B:
	case AML_NAME_CHAR_C:
	case AML_NAME_CHAR_D:
	case AML_NAME_CHAR_E:
	case AML_NAME_CHAR_F:
	case AML_NAME_CHAR_G:
	case AML_NAME_CHAR_H:
	case AML_NAME_CHAR_I:
	case AML_NAME_CHAR_J:
	case AML_NAME_CHAR_K:
	case AML_NAME_CHAR_L:
	case AML_NAME_CHAR_M:
	case AML_NAME_CHAR_N:
	case AML_NAME_CHAR_O:
	case AML_NAME_CHAR_P:
	case AML_NAME_CHAR_Q:
	case AML_NAME_CHAR_R:
	case AML_NAME_CHAR_S:
	case AML_NAME_CHAR_T:
	case AML_NAME_CHAR_U:
	case AML_NAME_CHAR_V:
	case AML_NAME_CHAR_W:
	case AML_NAME_CHAR_X:
	case AML_NAME_CHAR_Y:
	case AML_NAME_CHAR_Z:
	case AML_NAME_CHAR: // '_'
	case AML_ROOT_CHAR:
	case AML_PARENT_PREFIX_OP:
	case AML_DUAL_NAME_PREFIX:
	case AML_MULTI_NAME_PREFIX:
	case AML_NULL_NAME:
	    return 1;
	default:
	    return 0;
    }
}

