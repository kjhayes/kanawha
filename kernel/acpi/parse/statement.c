
#include <acpi/parse/statement.h>
#include <acpi/parse/opcode.h>
#include <kanawha/errno.h>

static struct acpi_term *
acpi_parse_def_break(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefBreak!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_break_point(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefBreakPoint!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_continue(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefContinue!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_fatal(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefFatal!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_if_else(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefIfElse!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_noop(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefNoop!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_notify(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefNotify!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_release(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefRelease!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_reset(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefReset!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_return(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefReturn!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_signal(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefSignal!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_sleep(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefSleep!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_stall(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefStall!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_while(
        struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse APCI DefWhile!\n");
    return NULL;
}

int
acpi_parse_statement_term(
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
        case AML_BREAK_OP:
            term = acpi_parse_def_break(ctx);
            break;
        case AML_BREAK_POINT_OP:
            term = acpi_parse_def_break_point(ctx);
            break;
        case AML_CONTINUE_OP:
            term = acpi_parse_def_continue(ctx);
            break;
        case AML_FATAL_OP:
            term = acpi_parse_def_fatal(ctx);
            break;
        case AML_IF_OP:
            term = acpi_parse_def_if_else(ctx);
            break;
        case AML_NOOP_OP:
            term = acpi_parse_def_noop(ctx);
            break;
        case AML_NOTIFY_OP:
            term = acpi_parse_def_notify(ctx);
            break;
        case AML_RELEASE_OP:
            term = acpi_parse_def_release(ctx);
            break;
        case AML_RESET_OP:
            term = acpi_parse_def_reset(ctx);
            break;
        case AML_RETURN_OP:
            term = acpi_parse_def_return(ctx);
            break;
        case AML_SIGNAL_OP:
            term = acpi_parse_def_signal(ctx);
            break;
        case AML_SLEEP_OP:
            term = acpi_parse_def_sleep(ctx);
            break;
        case AML_STALL_OP:
            term = acpi_parse_def_stall(ctx);
            break;
        case AML_WHILE_OP:
            term = acpi_parse_def_while(ctx);
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

