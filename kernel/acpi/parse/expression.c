
#include <acpi/parse/expression.h>
#include <acpi/parse/opcode.h>
#include <acpi/parse/logical_op.h>
#include <acpi/parse/arith_op.h>
#include <acpi/parse/invoke.h>

int
acpi_parse_expression_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;
    acpi_opcode_t op;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    res = acpi_parse_logical_op_term(
            ctx,
            term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_arith_op_term(
            ctx,
            term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_method_invocation_term(
            ctx,
            term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_try_parse_opcode(ctx, &op);
    if(res) {
        return res;
    }

    struct acpi_term *term = NULL;
    switch(op) {
        case AML_ACQUIRE_OP:
        case AML_BUFFER_OP:
        case AML_CONCAT_OP:
        case AML_CONCAT_RES_OP:
        case AML_COND_REF_OF_OP:
        case AML_COPY_OBJECT_OP:
        case AML_DEREF_OF_OP:
        case AML_FIND_SET_LEFT_BIT_OP:
        case AML_FIND_SET_RIGHT_BIT_OP:
        case AML_FROM_BCD_OP:
        case AML_INDEX_OP:
        case AML_MID_OP:
        case AML_LOAD_TABLE_OP:
        case AML_MATCH_OP:
        case AML_OBJECT_TYPE_OP:
        case AML_PACKAGE_OP:
        case AML_VAR_PACKAGE_OP:
        case AML_REF_OF_OP:
        case AML_SIZE_OF_OP:
        case AML_STORE_OP:
        case AML_TIMER_OP:
        case AML_TO_BCD_OP:
        case AML_TO_BUFFER_OP:
        case AML_TO_DECIMAL_STRING_OP:
        case AML_TO_HEX_STRING_OP:
        case AML_TO_INTEGER_OP:
        case AML_TO_STRING_OP:
        case AML_WAIT_OP:
            wprintk("Cannot handle ACPI %s\n", acpi_opcode_to_string(op));
            return -EUNIMPL;
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

