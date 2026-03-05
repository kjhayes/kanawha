
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/state.h>
#include <kanawha/errno.h>

int
acpi_interp_def_thermal_zone(struct acpi_interp_state *state)
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

    struct acpi_obj *thermal_zone_obj = acpi_create_thermal_zone_obj();
    if(thermal_zone_obj == NULL)
    {
        acpi_path_destroy(path);
        return -ENOMEM;
    }

    res = acpi_interp_create_named_object(state, path, thermal_zone_obj);
    if(res)
    {
        acpi_obj_put(thermal_zone_obj);
        acpi_path_destroy(path);
        return res;
    }

    acpi_obj_put(thermal_zone_obj);

    size_t term_rip = state->frame->rip;
    ssize_t term_len = pkglength - (state->frame->rip - base_rip);
    if(term_len < 0)
    {
        acpi_path_destroy(path);
        wprintk("acpi_interp_scope_op: scope AML has negative length!\n");
        return -EINVAL;
    }

    struct acpi_node *scope = acpi_interp_lookup(state, path);
    if(scope == NULL)
    {
        wprintk("acpi_interp_scope_op: failed to find scope \"");
        acpi_dump_path(do_printk, path);
        do_printk("\"!\n");
        acpi_path_destroy(path);
        return -EINVAL;
    }
    acpi_path_destroy(path);

    acpi_interp_advance_frame(state, term_len);

    res = acpi_interp_push_inner_frame(state,
                                       scope,
                                       term_rip,
                                       term_len,
                                       ACPI_INTERP_PUSH_FRAME_LOCAL);
    acpi_node_put(scope);
    if(res)
    {
        return res;
    }

    return 0;
}
