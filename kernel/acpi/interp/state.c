
#include <acpi/interp.h>
#include <acpi/interp/opcode.h>
#include <acpi/interp/state.h>
#include <acpi/object.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>

int
acpi_interp_state_init(struct acpi_interp_state *state)
{
    state->method_depth = 0;
    state->frame = NULL;
    return 0;
}

int
acpi_interp_push_frame(struct acpi_interp_state *state,
                       struct acpi_node *scope,
                       void *aml_data,
                       size_t aml_len,
                       unsigned long flags)
{
    struct acpi_interp_frame *frame = kzmalloc(sizeof(*frame), KM_KERNEL);
    if(frame == NULL)
    {
        return -ENOMEM;
    }

    if(scope == NULL)
    {
        DEBUG_ASSERT(KERNEL_ADDR(state->frame));
        DEBUG_ASSERT(KERNEL_ADDR(state->frame->scope));
        frame->scope = state->frame->scope;
    }
    else
    {
        frame->scope = scope;
    }
    acpi_node_get(frame->scope);

    frame->aml_data = aml_data;
    frame->aml_len = aml_len;
    frame->rip = 0;

    switch(flags)
    {
    case ACPI_INTERP_PUSH_FRAME_LOCAL:
        frame->parent = state->frame;
        state->frame = frame;
        break;
    case ACPI_INTERP_PUSH_FRAME_DEFERRED:
    {
        frame->parent = NULL;
        if(state->frame == NULL)
        {
            state->frame = frame;
        }
        else
        {
            struct acpi_interp_frame *root = state->frame;
            while(root->parent)
            {
                root = root->parent;
            }
            root->parent = frame;
        }
    }
    break;
    default:
        acpi_node_put(frame->scope);
        kfree(frame);
        return -EINVAL;
    }

    return 0;
}

int
acpi_interp_push_inner_frame(struct acpi_interp_state *state,
                             struct acpi_node *scope,
                             size_t base_rip,
                             size_t len,
                             unsigned long flags)
{
    if(state->frame == NULL)
    {
        return -EINVAL;
    }

    if(state->frame->aml_len < (base_rip + len))
    {
        return -EINVAL;
    }

    return acpi_interp_push_frame(state,
                                  scope,
                                  state->frame->aml_data + base_rip,
                                  len,
                                  flags);
}

int
acpi_interp_pop_frame(struct acpi_interp_state *state,
                      struct acpi_obj *ret_obj,
                      unsigned long flags)
{
    struct acpi_interp_frame *frame = state->frame;
    DEBUG_ASSERT(KERNEL_ADDR(frame));

    state->frame = state->frame->parent;

    acpi_node_put(frame->scope);
    kfree(frame);

    return 0;
}
