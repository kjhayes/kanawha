
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/state.h>
#include <acpi/interp/term_arg.h>
#include <acpi/object.h>
#include <kanawha/errno.h>

int
acpi_interp_def_buffer(struct acpi_interp_state *state,
                       struct acpi_obj **obj_out)
{
    int res;

    size_t base_rip = state->frame->rip;

    ssize_t pkglength = acpi_interp_pkglength(state);
    if(pkglength < 0)
    {
        return pkglength;
    }

    unsigned long buffer_size;
    res = acpi_interp_term_arg_to_integer(state, &buffer_size);
    if(res)
    {
        wprintk("acpi_interp_def_buffer: Failed to resolve buffer size!\n");
        return res;
    }

    void *initial_data = acpi_interp_current_ip(state);
    size_t initial_datalen = pkglength - (state->frame->rip - base_rip);

    struct acpi_obj *buffer =
        acpi_create_buffer_obj(buffer_size, initial_data, initial_datalen);
    if(buffer == NULL)
    {
        wprintk("acpi_interp_def_buffer: Failed to create Buffer object!\n");
        return -ENOMEM;
    }

    acpi_interp_advance_frame(state, initial_datalen);

    *obj_out = buffer;

    return 0;
}
