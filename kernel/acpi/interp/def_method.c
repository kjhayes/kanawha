
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/interp/term_arg.h>
#include <acpi/namespace.h>
#include <kanawha/errno.h>

int
acpi_interp_def_method(struct acpi_interp_state *state)
{
    int res;

    size_t base_rip = state->frame->rip;

    ssize_t pkglength = acpi_interp_pkglength(state);
    if(pkglength < 0)
    {
        return pkglength;
    }

    struct acpi_path *path;
    res = acpi_interp_name_string(state, &path);
    if(res)
    {
        return res;
    }

    uint8_t flags;
    res = acpi_interp_raw_u8(state, &flags);
    if(res)
    {
        acpi_path_destroy(path);
        return res;
    }

    unsigned int arg_count = flags & 0b111;
    unsigned int serialized = (flags >> 3) & 0b1;
    unsigned int sync_level = (flags >> 4) & 0b1111;

    void *aml_data = acpi_interp_current_ip(state);
    ssize_t aml_len = pkglength - (state->frame->rip - base_rip);

    struct acpi_obj *method_obj = acpi_create_method_obj(aml_data,
                                                         aml_len,
                                                         arg_count,
                                                         serialized,
                                                         sync_level);
    if(method_obj == NULL)
    {
        acpi_path_destroy(path);
        return -ENOMEM;
    }

    res = acpi_interp_create_named_object(state, path, method_obj);
    if(res)
    {
        acpi_obj_put(method_obj);
        acpi_path_destroy(path);
        return res;
    }

    acpi_obj_put(method_obj);
    acpi_path_destroy(path);

    acpi_interp_advance_frame(state, aml_len);

    return 0;
}
