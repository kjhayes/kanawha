
#include <acpi/interp/state.h>
#include <kanawha/errno.h>

static inline int
acpi_interp_peek_raw_u8(
	struct acpi_interp_state *state,
	uint8_t *out)
{
    if(acpi_interp_bytes_left_in_frame(state) < 1) {
	return -EINVAL;
    }
    *out = *((uint8_t*)acpi_interp_current_ip(state));
    return 0;
}
static inline int
acpi_interp_peek_raw_u16(
	struct acpi_interp_state *state,
	uint16_t *out)
{
    if(acpi_interp_bytes_left_in_frame(state) < 2) {
	return -EINVAL;
    }
    *out = *((uint16_t*)acpi_interp_current_ip(state));
    return 0;
}
static inline int
acpi_interp_peek_raw_u32(
	struct acpi_interp_state *state,
	uint32_t *out)
{
    if(acpi_interp_bytes_left_in_frame(state) < 4) {
	return -EINVAL;
    }
    *out = *((uint32_t*)acpi_interp_current_ip(state));
    return 0;
}
static inline int
acpi_interp_peek_raw_u64(
	struct acpi_interp_state *state,
	uint64_t *out)
{
    if(acpi_interp_bytes_left_in_frame(state) < 8) {
	return -EINVAL;
    }
    *out = *((uint64_t*)acpi_interp_current_ip(state));
    return 0;
}

static inline int
acpi_interp_raw_u8(
	struct acpi_interp_state *state,
	uint8_t *out)
{
    int res;
    res = acpi_interp_peek_raw_u8(state, out);
    if(res) {
	return res;
    }
    acpi_interp_advance_frame(state, 1);
    return 0;
}
static inline int
acpi_interp_raw_u16(
	struct acpi_interp_state *state,
	uint16_t *out)
{
    int res;
    res = acpi_interp_peek_raw_u16(state, out);
    if(res) {
	return res;
    }
    acpi_interp_advance_frame(state, 2);
    return 0;
}
static inline int
acpi_interp_raw_u32(
	struct acpi_interp_state *state,
	uint32_t *out)
{
    int res;
    res = acpi_interp_peek_raw_u32(state, out);
    if(res) {
	return res;
    }
    acpi_interp_advance_frame(state, 4);
    return 0;
}
static inline int
acpi_interp_raw_u64(
	struct acpi_interp_state *state,
	uint64_t *out)
{
    int res;
    res = acpi_interp_peek_raw_u64(state, out);
    if(res) {
	return res;
    }
    acpi_interp_advance_frame(state, 8);
    return 0;
}

