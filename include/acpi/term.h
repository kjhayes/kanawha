#ifndef __KANAWHA__ACPI_TERM_H__
#define __KANAWHA__ACPI_TERM_H__

#include <kanawha/list.h>
#include <acpi/object.h>

struct acpi_eval_ctx;

struct acpi_termlist {
    ilist_t terms;
};

struct acpi_term
{
    ilist_node_t list_node;

    // Private state of the term
    // (Either a pointer or a single integer
    union {
        void *ptr;
        uint64_t value;
    } priv;

    // Print a representation of this term to "printer"
    // Call "acpi_dump_term_indent()" before each line
    // If dump is invoked recursively, increase "depth"
    int(*dump)(
            struct acpi_term *self,
            printk_f *printer,
            int depth);

    // Evaluate this term
    // If "obj_out" is NULL this term is being
    //     evaluated as a statement.
    // If "obj_out" is non-NULL this term is being
    //     evaluated as an expression, and "obj_out" is
    //     the value of the expression.
    // Returns 0 on success, negative errno on failure
    int(*eval)(
            struct acpi_term *self,
            struct acpi_eval_ctx *ctx,
            struct acpi_obj **obj_out);

    // If NULL, nothing is done to free the term
    // After calling (self->destroy)(self), "self"
    // is considered an invalid pointer.
    int(*destroy)(struct acpi_term *self);
};

struct acpi_termlist *
acpi_create_empty_termlist(void);

int
acpi_destroy_termlist(
        struct acpi_termlist *terms);

int
acpi_destroy_term(
        struct acpi_term *term);

int
acpi_termlist_append(
        struct acpi_termlist *terms,
        struct acpi_term *term);

static inline void
acpi_dump_term_indent(
        printk_f *printer,
        int depth)
{
    for(int i = 0; i < depth; i++) {
        (*printer)("  ");
    }
}

int
acpi_dump_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth);

int
acpi_dump_termlist(
        struct acpi_termlist *list,
        printk_f *printer,
        int depth);

#endif
