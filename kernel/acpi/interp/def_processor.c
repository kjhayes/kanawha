
#include <acpi/interp/name.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/object.h>
#include <kanawha/errno.h>

int
acpi_interp_def_processor(struct acpi_interp_state *state)
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

    uint8_t procid;
    res = acpi_interp_raw_u8(state, &procid);
    if(res)
    {
        acpi_path_destroy(path);
        return res;
    }
    uint32_t pblkaddr;
    res = acpi_interp_raw_u32(state, &pblkaddr);
    if(res)
    {
        acpi_path_destroy(path);
        return res;
    }
    uint8_t pblklen;
    res = acpi_interp_raw_u8(state, &pblklen);
    if(res)
    {
        acpi_path_destroy(path);
        return res;
    }
    // TODO: Actually store the PBLK information somehow

    struct acpi_obj *device_obj = acpi_create_device_obj();
    if(device_obj == NULL)
    {
        acpi_path_destroy(path);
        return -ENOMEM;
    }

    res = acpi_interp_create_named_object(state, path, device_obj);
    if(res)
    {
        acpi_obj_put(device_obj);
        acpi_path_destroy(path);
        return res;
    }

    acpi_obj_put(device_obj);

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
