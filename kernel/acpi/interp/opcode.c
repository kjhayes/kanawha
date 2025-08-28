
#include <acpi/interp/opcode.h>

#include <kanawha/printk.h>
#include <kanawha/errno.h>

const char *
aml_opcode_to_string(aml_opcode_t opcode)
{
#define BUFLEN 32
    static char unknown_buffer[BUFLEN];

    switch(opcode)
    {
#define XLIST_CASE(__NAME, __VAL)\
        case __VAL: return "AML_" #__NAME;
        ACPI_AML_OPCODE_XLIST(XLIST_CASE)
#undef XLIST_CASE
        default:
	    snprintk(unknown_buffer, BUFLEN-1, "AML_UNKNOWN_OP(0x%x)", (unsigned int)opcode);
            unknown_buffer[BUFLEN-1] = '\0';
	    return unknown_buffer;
    }

#undef BUFLEN
}

ssize_t
aml_parse_opcode(
	void *data,
	size_t datalen,
        aml_opcode_t *out)
{
    int res;

    if(datalen == 0) {
	return -EINVAL;
    }

    uint8_t first_byte = ((uint8_t*)data)[0];
    int num_bytes = 1;

    aml_opcode_t op;
    if(first_byte == ACPI_AML_EXT_OP_PREFIX)
    {
	if(datalen <= 1) {
	    return -EINVAL;
	}
	uint8_t second_byte = ((uint8_t*)data)[1];
        op = (0x5B00) | (uint16_t)second_byte;
	num_bytes++;
    }
    else if(first_byte == ACPI_AML_NOT_OP_PREFIX)
    {
	if(datalen > 1) {
	    uint8_t second_byte = ((uint8_t*)data)[1];
            switch(second_byte) {
                case 0x93:
                case 0x94:
                case 0x95:
                    op = (0x9200) | (uint16_t)second_byte;
		    num_bytes++;
                    break;
                default:
                    op = AML_LNOT_OP;
                    break;
            }
	} else
	{
            op = (uint16_t)first_byte;
	}
    }
    else
    {
        op = (uint16_t)first_byte;
    }

    *out = op;

    return num_bytes;
}

int
acpi_interp_peek_aml_opcode(
	struct acpi_interp_state *state,
	aml_opcode_t *out)
{
    ssize_t opcode_len = aml_parse_opcode(
	    state->frame->aml_data + state->frame->rip,
	    state->frame->aml_len - state->frame->rip,
	    out);
    if(opcode_len <= 0) {
	return -EINVAL;
    }
    return 0;
}

int
acpi_interp_aml_opcode(
	struct acpi_interp_state *state,
	aml_opcode_t *out)
{
    ssize_t opcode_len = aml_parse_opcode(
	    state->frame->aml_data + state->frame->rip,
	    state->frame->aml_len - state->frame->rip,
	    out);
    if(opcode_len <= 0) {
	return -EINVAL;
    }
    acpi_interp_advance_frame(state, opcode_len);
    return 0;
}

