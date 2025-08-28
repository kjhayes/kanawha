
#include <acpi/interp/pkglength.h>
#include <acpi/interp/state.h>
#include <acpi/interp/raw.h>

ssize_t
acpi_interp_pkglength(
        struct acpi_interp_state *state)
{
    int res;

    uint8_t lead_byte;
    res = acpi_interp_raw_u8(state, &lead_byte);
    if(res < 0) {
        return res;
    }

    uint8_t num_trailing_bytes = (lead_byte>>6) & 0b11;

    if(num_trailing_bytes == 0) {
        return (uint32_t)(lead_byte & 0x3F);
    }

    uint32_t value = lead_byte & 0xF;
    for(size_t i = 0; i < num_trailing_bytes; i++) {
        int shift = (i*8) + 4;
        uint8_t trail_byte;
        res = acpi_interp_raw_u8(state, &trail_byte);
        if(res < 0) {
            return res;
        }
        value |= (((uint32_t)trail_byte)<<shift);
    }

    return value;
}

int
acpi_interp_push_pkg_frame(
	struct acpi_interp_state *state)
{
    int res;

    size_t base_rip = state->frame->rip;

    ssize_t pkglength = acpi_interp_pkglength(state);
    if(pkglength < 0) {
	return pkglength;
    }

    // How long was the "pkglength" field itself
    ssize_t pkglength_len = state->frame->rip - base_rip;

    DEBUG_ASSERT(pkglength - pkglength_len >= 0);

    // Make it so our "return address" is after the package data
    acpi_interp_advance_frame(state, pkglength - pkglength_len);

    // Push the package as a frame
    res = acpi_interp_push_inner_frame(
	    state,
	    NULL,
	    base_rip,
	    pkglength,
	    ACPI_INTERP_PUSH_FRAME_LOCAL);
    if(res) {
	wprintk("acpi_interp_push_pkg_frame: Failed to push inner frame!\n");
	return res;
    }

    // No need to re-parse the pkglength field
    acpi_interp_advance_frame(state, pkglength_len);

    return 0;
}

