
#include <acpi/interp/name.h>
#include <acpi/interp/named_reference.h>
#include <acpi/interp/namespace.h>
#include <acpi/interp/opcode.h>
#include <acpi/interp/pkglength.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/interp/term_arg.h>
#include <acpi/object.h>
#include <kanawha/errno.h>

int
acpi_interp_def_package(struct acpi_interp_state *state,
                        struct acpi_obj **obj_out)
{
    int res;

    size_t base_rip = state->frame->rip;

    ssize_t pkglength = acpi_interp_pkglength(state);
    if(pkglength < 0)
    {
        return pkglength;
    }

    uint8_t num_elements;
    res = acpi_interp_raw_u8(state, &num_elements);
    if(res)
    {
        return res;
    }

    void *element_data = acpi_interp_current_ip(state);
    size_t element_datalen = pkglength - (state->frame->rip - base_rip);

    struct acpi_obj *package = acpi_create_package_obj(num_elements);
    if(package == NULL)
    {
        wprintk("acpi_interp_def_package: Failed to create Package object!\n");
        return -ENOMEM;
    }

    size_t end_rip = state->frame->rip + element_datalen;
    size_t initial_elem_index = 0;
    while(state->frame->rip < end_rip)
    {

        struct acpi_obj *inner_obj;

        aml_opcode_t opcode;
        acpi_interp_peek_aml_opcode(state, &opcode);
        if(opcode != AML_ZERO_OP && acpi_opcode_is_name_string(opcode))
        {
            struct acpi_obj *named_ref;
            res = acpi_interp_name_string_as_named_reference(state, &named_ref);
            if(res)
            {
                acpi_obj_put(package);
                return res;
            }
            inner_obj = acpi_obj_data_ref_obj(named_ref);
            acpi_obj_put(named_ref);
            if(inner_obj == NULL)
            {
                acpi_obj_put(package);
                return -EINVAL;
            }
        }
        else
        {
            res = acpi_interp_term_arg(state, &inner_obj);
            if(res)
            {
                acpi_obj_put(package);
                return res;
            }
        }

        acpi_package_set_obj(package, initial_elem_index, inner_obj);
        acpi_obj_put(inner_obj);

        initial_elem_index++;

        if(state->frame->rip > end_rip)
        {
            acpi_obj_put(package);
            return -EINVAL;
        }
    }

    DEBUG_ASSERT(state->frame->rip == end_rip);

    *obj_out = package;

    return 0;
}
