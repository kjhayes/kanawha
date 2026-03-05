#ifndef __KANAWHA__ACPI_INTERP_STATE_H__
#define __KANAWHA__ACPI_INTERP_STATE_H__

#include <acpi/namespace.h>
#include <acpi/object.h>
#include <kanawha/errno.h>
#include <kanawha/list.h>

struct acpi_interp_frame
{
    struct acpi_interp_frame *parent;

    struct acpi_node *scope;

    void *aml_data;
    size_t aml_len;
    size_t rip;
};

struct acpi_interp_state
{
    struct acpi_interp_frame *frame;
    unsigned long method_depth;
};

int
acpi_interp_state_init(struct acpi_interp_state *state);

#define ACPI_INTERP_PUSH_FRAME_LOCAL (0)
#define ACPI_INTERP_PUSH_FRAME_DEFERRED (1)

int
acpi_interp_push_frame(struct acpi_interp_state *state,
                       struct acpi_node *scope,
                       void *aml_data,
                       size_t aml_len,
                       unsigned long flags);

int
acpi_interp_push_inner_frame(struct acpi_interp_state *state,
                             struct acpi_node *scope,
                             size_t base_rip,
                             size_t len,
                             unsigned long flags);

int
acpi_interp_pop_frame(struct acpi_interp_state *state,
                      struct acpi_obj *ret_obj,
                      unsigned long flags);

static inline size_t
acpi_interp_bytes_left_in_frame(struct acpi_interp_state *state)
{
    DEBUG_ASSERT(KERNEL_ADDR(state->frame));
    DEBUG_ASSERT(state->frame->rip <= state->frame->aml_len);
    return state->frame->aml_len - state->frame->rip;
}

static inline void *
acpi_interp_current_ip(struct acpi_interp_state *state)
{
    DEBUG_ASSERT(KERNEL_ADDR(state->frame));
    DEBUG_ASSERT(state->frame->rip <= state->frame->aml_len);
    return state->frame->aml_data + state->frame->rip;
}

static inline void
acpi_interp_advance_frame(struct acpi_interp_state *state, size_t amt)
{
    DEBUG_ASSERT(KERNEL_ADDR(state->frame));
    DEBUG_ASSERT(state->frame->rip + amt <= state->frame->aml_len);
    state->frame->rip += amt;
}

static inline struct acpi_node *
acpi_interp_current_scope(struct acpi_interp_state *state)
{
    DEBUG_ASSERT(KERNEL_ADDR(state->frame));
    return state->frame->scope;
}

static inline int
acpi_interp_set_scope(struct acpi_interp_state *state, struct acpi_node *scope)
{
    if(state->frame == NULL)
    {
        return -EINVAL;
    }
    acpi_node_get(scope);
    struct acpi_node *old_scope = state->frame->scope;
    state->frame->scope = scope;
    acpi_node_put(old_scope);
    return 0;
}

#endif
