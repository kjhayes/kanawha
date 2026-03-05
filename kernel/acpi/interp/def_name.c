
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/interp/term_arg.h>
#include <acpi/namespace.h>
#include <kanawha/errno.h>

int
acpi_interp_def_name(struct acpi_interp_state *state)
{
    int res;

    struct acpi_path *name_string;
    res = acpi_interp_name_string(state, &name_string);
    if(res)
    {
        wprintk("acpi_interp_def_name: Malformed name string!\n");
        return res;
    }

    struct acpi_obj *obj;
    res = acpi_interp_term_arg(state, &obj);
    if(res)
    {
        wprintk("acpi_interp_def_name: Failed to resolve term to object!\n");
        acpi_path_destroy(name_string);
        return res;
    }

    res = acpi_node_create_named_object(acpi_interp_current_scope(state),
                                        name_string,
                                        obj);
    if(res)
    {
        wprintk("acpi_interp_def_name: Failed to add object to namespace \"");
        acpi_dump_path(do_printk, name_string);
        do_printk("\" at scope \"");
        acpi_node_dump_path(do_printk, state->frame->scope);
        do_printk("\"\n");
        acpi_path_destroy(name_string);
        acpi_obj_put(obj);
        return res;
    }

    acpi_path_destroy(name_string);
    acpi_obj_put(obj);

    return 0;
}
