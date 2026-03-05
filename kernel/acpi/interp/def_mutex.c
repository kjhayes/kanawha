
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/interp/term_arg.h>
#include <acpi/namespace.h>
#include <kanawha/errno.h>

int
acpi_interp_def_mutex(struct acpi_interp_state *state)
{
    int res;

    struct acpi_path *name_string;
    res = acpi_interp_name_string(state, &name_string);
    if(res)
    {
        wprintk("acpi_interp_def_mutex: Malformed name string!\n");
        return res;
    }

    uint8_t flags;
    res = acpi_interp_raw_u8(state, &flags);
    if(res)
    {
        wprintk("acpi_interp_def_mutex: Failed to read flags!\n");
        acpi_path_destroy(name_string);
        return res;
    }

    unsigned int sync_level = flags & 0xF;

    struct acpi_obj *obj = acpi_create_mutex_obj(sync_level);
    if(obj == NULL)
    {
        wprintk("acpi_interp_def_mutex: Failed to create mutex object!\n");
        acpi_path_destroy(name_string);
        return -ENOMEM;
    }

    res = acpi_interp_create_named_object(state, name_string, obj);
    if(res)
    {
        wprintk("acpi_interp_def_mutex: Failed to add mutex object to "
                "namespace!\n");
        acpi_path_destroy(name_string);
        acpi_obj_put(obj);
        return res;
    }

    acpi_path_destroy(name_string);
    acpi_obj_put(obj);
    return 0;
}
