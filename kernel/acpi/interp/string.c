
#include <acpi/interp/opcode.h>
#include <acpi/interp/state.h>
#include <acpi/object.h>

#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

int
acpi_interp_string_after_opcode(struct acpi_interp_state *state,
                                struct acpi_obj **out)
{
    size_t room_left = acpi_interp_bytes_left_in_frame(state);
    char *data = acpi_interp_current_ip(state);

    int found_null = 0;
    size_t strlen = 0;
    while(strlen < room_left)
    {
        if(data[strlen] == '\0')
        {
            found_null = 1;
            break;
        }
        strlen++;
    }

    if(!found_null)
    {
        return -EINVAL;
    }

    char *buffer = kmalloc(strlen + 1, KM_KERNEL);
    if(buffer == NULL)
    {
        return -ENOMEM;
    }

    memcpy(buffer, data, strlen);
    buffer[strlen] = '\0';

    struct acpi_obj *str = acpi_create_string_obj(buffer);
    kfree(buffer);
    if(str == NULL)
    {
        return -ENOMEM;
    }

    acpi_interp_advance_frame(state, strlen + 1);

    *out = str;

    return 0;
}

int
acpi_interp_string(struct acpi_interp_state *state, struct acpi_obj **out)
{
    int res;

    aml_opcode_t opcode;
    res = acpi_interp_aml_opcode(state, &opcode);
    if(res)
    {
        return res;
    }

    if(opcode != AML_STRING_PREFIX)
    {
        return -EINVAL;
    }

    return acpi_interp_string_after_opcode(state, out);
}
