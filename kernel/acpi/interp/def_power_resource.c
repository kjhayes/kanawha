
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/object.h>
#include <kanawha/errno.h>

int
acpi_interp_def_power_resource(struct acpi_interp_state *state)
{
    int res;

    res = acpi_interp_push_pkg_frame(state);
    if(res)
    {
        return res;
    }

    struct acpi_path *path;
    res = acpi_interp_name_string(state, &path);
    if(res)
    {
        return res;
    }

    uint8_t system_level;
    res = acpi_interp_raw_u8(state, &system_level);
    if(res)
    {
        acpi_path_destroy(path);
        return res;
    }
    uint16_t resource_order;
    res = acpi_interp_raw_u16(state, &resource_order);
    if(res)
    {
        acpi_path_destroy(path);
        return res;
    }

    struct acpi_obj *power_res_obj =
        acpi_create_power_resource_obj(system_level, resource_order);
    if(power_res_obj == NULL)
    {
        acpi_path_destroy(path);
        return -ENOMEM;
    }

    res = acpi_interp_create_named_object(state, path, power_res_obj);
    if(res)
    {
        acpi_obj_put(power_res_obj);
        acpi_path_destroy(path);
        return res;
    }

    acpi_obj_put(power_res_obj);

    struct acpi_node *scope = acpi_interp_lookup(state, path);
    acpi_path_destroy(path);
    if(scope == NULL)
    {
        return -EINVAL;
    }

    res = acpi_interp_set_scope(state, scope);
    if(res)
    {
        return res;
    }

    acpi_node_put(scope);

    return 0;
}
