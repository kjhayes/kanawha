
#define KEEP_ACPI_AML_OPCODE_XLIST
#include <acpi/parse/opcode.h>

#include <acpi/parse/ctx.h>

const char *
acpi_opcode_to_string(acpi_opcode_t opcode)
{
    switch(opcode)
    {
#define XLIST_CASE(__NAME, __VAL)\
        case __VAL: return "AML_" #__NAME;
        ACPI_AML_OPCODE_XLIST(XLIST_CASE)
#undef XLIST_CASE
        default: return "AML_UNKNOWN_OP";
    }
}

int
acpi_try_parse_opcode(
        struct acpi_parse_ctx *ctx,
        acpi_opcode_t *out)
{
    int res;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    uint8_t byte;
    res = acpi_ctx_pop_u8(ctx, &byte);
    if(res) {
        acpi_ctx_restore(ctx, &chk);
        return res;
    }

    acpi_opcode_t op;
    if(byte == ACPI_AML_EXT_OP_PREFIX)
    {
        res = acpi_ctx_pop_u8(ctx, &byte);
        if(res) {
            acpi_ctx_restore(ctx, &chk);
            return res;
        }
        op = (0x5B00) | (uint16_t)byte;
    }
    else if(byte == ACPI_AML_NOT_OP_PREFIX)
    {
        struct acpi_parse_checkpoint chk_not;
        acpi_ctx_save(ctx, &chk_not);
        res = acpi_ctx_pop_u8(ctx, &byte);
        if(res) {
            acpi_ctx_restore(ctx, &chk);
            return res;
        }
        switch(byte) {
            case 0x93:
            case 0x94:
            case 0x95:
                op = (0x9200) | (uint16_t)byte;
                break;
            default:
                acpi_ctx_restore(ctx, &chk_not);
                op = AML_LNOT_OP;
                break;
        }
    }
    else
    {
        op = (uint16_t)byte;
    }

    if(out != NULL) {
        *out = op;
    }

    return 0;
}

