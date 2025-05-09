
#include <acpi/parse/arith_op.h>
#include <acpi/parse/opcode.h>
#include <acpi/parse/term.h>
#include <acpi/parse/target.h>
#include <acpi/term.h>
#include <acpi/terms/arith_op.h>
#include <kanawha/errno.h>
#include <kanawha/printk.h>

static struct acpi_term *
acpi_parse_unary_op(
        struct acpi_parse_ctx *ctx,
        enum acpi_unary_arith_op op)
{
    int res;

    struct acpi_term *arg;
    struct acpi_target *target;

    res = acpi_parse_operand(ctx, &arg);
    if(res) {
        wprintk("acpi_parse_unary_op: Failed to parse operand!\n");
        return NULL;
    }

    printk("NOT Parsed Operand: ");
    acpi_dump_term(arg, do_printk, 0);

    res = acpi_parse_target(ctx, &target);
    if(res) {
        wprintk("acpi_parse_unary_op: Failed to parse target!\n");
        acpi_destroy_term(arg);
        return NULL;
    }

    struct acpi_term *term = acpi_create_unary_arith_term(
            op,
            arg,
            target);
    if(term == NULL) {
        wprintk("acpi_parse_unary_op: Failed to create term struct!\n");
        acpi_destroy_term(arg);
        acpi_destroy_target(target);
        return NULL;

    }

    return term;
}

static struct acpi_term *
acpi_parse_binary_op(
        struct acpi_parse_ctx *ctx,
        enum acpi_binary_arith_op op)
{
    int res;

    struct acpi_term *arg0;
    struct acpi_term *arg1;
    struct acpi_target *target;

    res = acpi_parse_operand(ctx, &arg0);
    if(res) {
        return NULL;
    }
    res = acpi_parse_operand(ctx, &arg1);
    if(res) {
        acpi_destroy_term(arg0);
        return NULL;
    }

    res = acpi_parse_target(ctx, &target);
    if(res) {
        acpi_destroy_term(arg0);
        acpi_destroy_term(arg1);
        return NULL;
    }

    struct acpi_term *term = acpi_create_binary_arith_term(
            op,
            arg0,
            arg1,
            target);
    if(term == NULL) {
        acpi_destroy_term(arg0);
        acpi_destroy_term(arg1);
        acpi_destroy_target(target);
        return NULL;

    }

    return term;
}

static struct acpi_term *
acpi_parse_def_add(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefAdd\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_decrement(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefDecrement\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_divide(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefDivide\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_increment(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefIncrement\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_mod(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefMod\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_multiply(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefMultiply\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_nand(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefNand\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_nor(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefNor\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_not(struct acpi_parse_ctx *ctx)
{
    struct acpi_term *term = acpi_parse_unary_op(ctx, ACPI_UNARY_ARITH_OP_NOT);
    if(term == NULL) {
        wprintk("Failed to parse ACPI DefNot Term!\n");
        return NULL;
    }
    return term;
}
static struct acpi_term *
acpi_parse_def_or(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefOr\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_shift_left(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefShiftLeft\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_shift_right(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefShiftRight\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_subtract(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefSubtract\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_xor(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefXor\n");
    return NULL;
}

int
acpi_parse_arith_op_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;
    acpi_opcode_t op;
    res = acpi_try_parse_opcode(ctx, &op);
    if(res) {
        return res;
    }

    struct acpi_term *term = NULL;
    switch(op) {
        case AML_ADD_OP:
            term = acpi_parse_def_add(ctx);
            break;
        case AML_DECREMENT_OP:
            term = acpi_parse_def_decrement(ctx);
            break;
        case AML_DIVIDE_OP:
            term = acpi_parse_def_divide(ctx);
            break;
        case AML_INCREMENT_OP:
            term = acpi_parse_def_increment(ctx);
            break;
        case AML_MOD_OP:
            term = acpi_parse_def_mod(ctx);
            break;
        case AML_MULTIPLY_OP:
            term = acpi_parse_def_multiply(ctx);
            break;
        case AML_NAND_OP:
            term = acpi_parse_def_nand(ctx);
            break;
        case AML_NOR_OP:
            term = acpi_parse_def_nor(ctx);
            break;
        case AML_NOT_OP:
            term = acpi_parse_def_not(ctx);
            break;
        case AML_OR_OP:
            term = acpi_parse_def_or(ctx);
            break;
        case AML_SHIFT_LEFT_OP:
            term = acpi_parse_def_shift_left(ctx);
            break;
        case AML_SHIFT_RIGHT_OP:
            term = acpi_parse_def_shift_right(ctx);
            break;
        case AML_SUBTRACT_OP:
            term = acpi_parse_def_subtract(ctx);
            break;
        case AML_XOR_OP:
            term = acpi_parse_def_xor(ctx);
            break;
        default:
            return -EINVAL;
    }

    if(term == NULL) {
        return -EINVAL;
    }

    if(term_out != NULL) {
        *term_out = term;
    }

    return 0;
}

