
#include <acpi/parse/logical_op.h>
#include <acpi/parse/opcode.h>
#include <acpi/term.h>
#include <kanawha/errno.h>

static struct acpi_term *
acpi_parse_def_land(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLAnd!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lequal(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLEqual!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lgreater(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLGreater!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lgreater_equal(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLGreaterEqual!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lless(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLLess!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lless_equal(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLLessEqual!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lnot(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLNot!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lnot_equal(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLNotEqual!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_lor(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefLOr!\n");
    return NULL;
}

int
acpi_parse_logical_op_term(
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
        case AML_LAND_OP:
            term = acpi_parse_def_land(ctx);
            break;
        case AML_LEQUAL_OP:
            term = acpi_parse_def_lequal(ctx);
            break;
        case AML_LGREATER_OP:
            term = acpi_parse_def_lgreater(ctx);
            break;
        case AML_LGREATER_EQUAL_OP:
            term = acpi_parse_def_lgreater_equal(ctx);
            break;
        case AML_LLESS_OP:
            term = acpi_parse_def_lless(ctx);
            break;
        case AML_LLESS_EQUAL_OP:
            term = acpi_parse_def_lless_equal(ctx);
            break;
        case AML_LNOT_OP:
            term = acpi_parse_def_lnot(ctx);
            break;
        case AML_LNOT_EQUAL_OP:
            term = acpi_parse_def_lnot_equal(ctx);
            break;
        case AML_LOR_OP:
            term = acpi_parse_def_lor(ctx);
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

