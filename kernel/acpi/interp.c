
#include <acpi/interp.h>
#include <acpi/interp/opcode.h>
#include <acpi/interp/state.h>
#include <acpi/object.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>

static int
acpi_interp_step(struct acpi_interp_state *state)
{
    int res;

    struct acpi_interp_frame *frame = state->frame;

    DEBUG_ASSERT(KERNEL_ADDR(frame));

    if(frame->rip >= frame->aml_len)
    {
        // implicit return
        return acpi_interp_pop_frame(state, acpi_create_uninitialized_obj(), 0);
    }

    aml_opcode_t opcode;
    res = acpi_interp_aml_opcode(state, &opcode);
    if(res)
    {
        return res;
    }

    switch(opcode)
    {
    case AML_SCOPE_OP:
        res = acpi_interp_scope_op(state);
        break;
    case AML_OP_REGION_OP:
        res = acpi_interp_def_op_region(state);
        break;
    case AML_OP_REGION_FIELDS_OP:
        res = acpi_interp_def_field(state);
        break;
    case AML_CREATE_BIT_FIELD_OP:
        res = acpi_interp_def_create_bit_field(state);
        break;
    case AML_CREATE_BYTE_FIELD_OP:
        res = acpi_interp_def_create_byte_field(state);
        break;
    case AML_CREATE_WORD_FIELD_OP:
        res = acpi_interp_def_create_word_field(state);
        break;
    case AML_CREATE_DWORD_FIELD_OP:
        res = acpi_interp_def_create_dword_field(state);
        break;
    case AML_CREATE_QWORD_FIELD_OP:
        res = acpi_interp_def_create_qword_field(state);
        break;
    case AML_CREATE_FIELD_OP:
        res = acpi_interp_def_create_field(state);
        break;
    case AML_METHOD_OP:
        res = acpi_interp_def_method(state);
        break;
    case AML_DEVICE_OP:
        res = acpi_interp_def_device(state);
        break;
    case AML_PROCESSOR_OP: // PROCESSOR_OP is deprecated in the latest
                           // version
        res = acpi_interp_def_processor(state);
        break;
    case AML_THERMAL_ZONE_OP:
        res = acpi_interp_def_thermal_zone(state);
        break;
    case AML_POWER_RES_OP:
        res = acpi_interp_def_power_resource(state);
        break;
    case AML_NAME_OP:
        res = acpi_interp_def_name(state);
        break;
    case AML_ALIAS_OP:
        res = acpi_interp_def_alias(state);
        break;
    case AML_MUTEX_OP:
        res = acpi_interp_def_mutex(state);
        break;
    default:
        printk("acpi_interp_step: Cannot handle %s\n",
               aml_opcode_to_string(opcode));
        return -EUNIMPL;
    }

    if(res)
    {
        wprintk("acpi_interp_step: Failed to handle %s (err=%s)\n",
                aml_opcode_to_string(opcode),
                errnostr(res));
        return res;
    }

    return 0;
}

int
acpi_interpret_aml(struct acpi_node *scope, void *aml_data, size_t aml_len)
{
    int res;

    struct acpi_interp_state state;

    acpi_interp_state_init(&state);

    state.frame = NULL;
    res = acpi_interp_push_frame(&state,
                                 scope,
                                 aml_data,
                                 aml_len,
                                 ACPI_INTERP_PUSH_FRAME_LOCAL);
    if(res)
    {
        return res;
    }

    while(state.frame != NULL)
    {
        res = acpi_interp_step(&state);
        if(res)
        {
            return res;
        }
    }

    return 0;
}
