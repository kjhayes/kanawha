
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/interp/term_arg.h>
#include <acpi/namespace.h>
#include <kanawha/errno.h>

int
acpi_interp_def_alias(struct acpi_interp_state *state)
{
    int res;

    struct acpi_path *src_path;
    res = acpi_interp_name_string(state, &src_path);
    if(res)
    {
        wprintk("acpi_interp_def_alias: Malformed name string!\n");
        return res;
    }

    struct acpi_path *alias_path;
    res = acpi_interp_name_string(state, &alias_path);
    if(res)
    {
        wprintk("acpi_interp_def_alias: Malformed name string!\n");
        acpi_path_destroy(src_path);
        return res;
    }

    struct acpi_obj *obj;
    obj = acpi_interp_get_named_object(state, src_path);
    acpi_path_destroy(src_path);
    if(obj == NULL)
    {
        wprintk("acpi_interp_def_alias: Failed to resolve term to object!\n");
        acpi_path_destroy(alias_path);
        return -ENXIO;
    }

    res = acpi_node_create_named_object(acpi_interp_current_scope(state),
                                        alias_path,
                                        obj);
    if(res)
    {
        wprintk("acpi_interp_def_alias: Failed to add object to namespace \"");
        acpi_dump_path(do_printk, alias_path);
        do_printk("\" at scope \"");
        acpi_node_dump_path(do_printk, state->frame->scope);
        do_printk("\"\n");
        acpi_path_destroy(alias_path);
        acpi_obj_put(obj);
        return res;
    }

    acpi_path_destroy(alias_path);
    acpi_obj_put(obj);

    return 0;
}
