
#include <acpi/terms/arith_op.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>

struct acpi_unary_arith_term
{
    struct acpi_term term;

    enum acpi_unary_arith_op op;
    struct acpi_term *arg;
    struct acpi_target *target;
};
struct acpi_binary_arith_term
{
    struct acpi_term term;

    enum acpi_binary_arith_op op;
    struct acpi_term *arg0;
    struct acpi_term *arg1;
    struct acpi_target *target;
};

static const char *
acpi_unary_arith_op_to_string(
        enum acpi_unary_arith_op op)
{
    switch(op) {
        case ACPI_UNARY_ARITH_OP_NOT: return "NOT";
        default:
            return "UNKNOWN-UNARY-OP";
    }
}

static const char *
acpi_binary_arith_op_to_string(
        enum acpi_binary_arith_op op)
{
    switch(op) {
        case ACPI_BINARY_ARITH_OP_ADD: return "ADD";
        default:
            return "UNKNOWN-BINARY-OP";
    }
}

static int
__acpi_destroy_unary_arith_term(
        struct acpi_term *term)
{
    struct acpi_unary_arith_term *uterm =
        container_of(term, struct acpi_unary_arith_term, term);

    acpi_destroy_term(uterm->arg);
    acpi_destroy_target(uterm->target);
    kfree(uterm);

    return 0;
}

static int
__acpi_eval_unary_arith_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj_out)
{
    struct acpi_unary_arith_term *uterm =
        container_of(term, struct acpi_unary_arith_term, term);

    eprintk("Tried to evaluate ACPI unary operator term!\n");

    return -EUNIMPL;
}

static int
__acpi_dump_unary_arith_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    struct acpi_unary_arith_term *uterm =
        container_of(term, struct acpi_unary_arith_term, term);

    acpi_dump_term_indent(printer, depth);
    (*printer)("%s(\n", acpi_unary_arith_op_to_string(uterm->op));

    acpi_dump_term(
            uterm->arg,
            printer,
            depth+1);

    acpi_dump_term_indent(printer, depth);
    (*printer)(",\n");

    acpi_dump_target(
            uterm->target,
            printer,
            depth+1);

    acpi_dump_term_indent(printer, depth);
    (*printer)(")\n");

    return 0;
}

struct acpi_term *
acpi_create_unary_arith_term(
        enum acpi_unary_arith_op op,
        struct acpi_term *arg,
        struct acpi_target *target)
{
    struct acpi_unary_arith_term *term =
        kmalloc(sizeof(struct acpi_unary_arith_term), KM_KERNEL);
    if(term == NULL) {
        return NULL;
    }

    term->op = op;
    term->arg = arg;
    term->target = target;

    term->term.destroy = __acpi_destroy_unary_arith_term;
    term->term.eval = __acpi_eval_unary_arith_term;
    term->term.dump = __acpi_dump_unary_arith_term;

    return &term->term;
}

static int
__acpi_destroy_binary_arith_term(
        struct acpi_term *term)
{
    struct acpi_binary_arith_term *uterm =
        container_of(term, struct acpi_binary_arith_term, term);

    acpi_destroy_term(uterm->arg0);
    acpi_destroy_term(uterm->arg1);
    acpi_destroy_target(uterm->target);
    kfree(uterm);

    return 0;
}

static int
__acpi_eval_binary_arith_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj_out)
{
    struct acpi_binary_arith_term *uterm =
        container_of(term, struct acpi_binary_arith_term, term);

    eprintk("Tried to evaluate ACPI binary operator term!\n");

    return -EUNIMPL;
}

static int
__acpi_dump_binary_arith_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    struct acpi_binary_arith_term *uterm =
        container_of(term, struct acpi_binary_arith_term, term);

    acpi_dump_term_indent(printer, depth);
    (*printer)("%s(\n", acpi_binary_arith_op_to_string(uterm->op));

    acpi_dump_term(
            uterm->arg0,
            printer,
            depth+1);

    acpi_dump_term_indent(printer, depth);
    (*printer)(",\n");

    acpi_dump_term(
            uterm->arg1,
            printer,
            depth+1);

    acpi_dump_term_indent(printer, depth);
    (*printer)(",\n");
    acpi_dump_target(
            uterm->target,
            printer,
            depth+1);

    acpi_dump_term_indent(printer, depth);
    (*printer)(")\n");

    return 0;
}

struct acpi_term *
acpi_create_binary_arith_term(
        enum acpi_binary_arith_op op,
        struct acpi_term *arg0,
        struct acpi_term *arg1,
        struct acpi_target *target)
{
    struct acpi_binary_arith_term *term =
        kmalloc(sizeof(struct acpi_binary_arith_term), KM_KERNEL);
    if(term == NULL) {
        return NULL;
    }

    term->op = op;
    term->arg0 = arg0;
    term->arg1 = arg1;
    term->target = target;

    term->term.destroy = __acpi_destroy_binary_arith_term;
    term->term.eval = __acpi_eval_binary_arith_term;
    term->term.dump = __acpi_dump_binary_arith_term;

    return &term->term;
}
