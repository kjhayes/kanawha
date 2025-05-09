
#include <acpi/parse/constants.h>
#include <acpi/parse/ctx.h>
#include <acpi/parse/opcode.h>
#include <acpi/terms/constants.h>
#include <acpi/term.h>

#include <kanawha/kmalloc.h>

int
acpi_parse_integer_const(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    acpi_opcode_t opcode;
    res = acpi_try_parse_opcode(ctx, &opcode);
    if(res) {
        return res;
    }

    uint8_t  byte;
    uint16_t word;
    uint32_t dword;
    uint64_t qword;

    struct acpi_term *term = NULL;

    switch(opcode) {
        case AML_BYTE_PREFIX:
            res = acpi_ctx_pop_u8(ctx, &byte);
            if(res) {
                return res;
            }
            term = acpi_create_byte_const_term(byte);
            break;
        case AML_WORD_PREFIX:
            res = acpi_ctx_pop_u16(ctx, &word);
            if(res) {
                return res;
            }
            term = acpi_create_word_const_term(byte);
            break;
        case AML_DWORD_PREFIX:
            res = acpi_ctx_pop_u32(ctx, &dword);
            if(res) {
                return res;
            }
            term = acpi_create_dword_const_term(dword);
            break;
        case AML_QWORD_PREFIX:
            res = acpi_ctx_pop_u64(ctx, &qword);
            if(res) {
                return res;
            }
            term = acpi_create_qword_const_term(qword);
            break;
        case AML_ZERO_OP:
            term = acpi_create_zero_term();
            break;
        case AML_ONE_OP:
            term = acpi_create_one_term();
            break;
        case AML_ONES_OP:
            term = acpi_create_ones_term();
            break;
        case AML_REVISION_OP:
            term = acpi_create_revision_term();
            break;
        default:
            return -EINVAL;
    }

    if(term == NULL) {
        return -ENOMEM;
    }

    if(term_out != NULL) {
        *term_out = term;
    } else {
        acpi_destroy_term(term);
    }

    return 0;
}

int
acpi_parse_string_const(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    acpi_opcode_t opcode;
    res = acpi_try_parse_opcode(ctx, &opcode);
    if(res) {
        return res;
    }

    if(opcode != AML_STRING_PREFIX) {
        return -EINVAL;
    }

    size_t len = 0;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    while(1) {
        uint8_t byte;
        res = acpi_ctx_pop_u8(ctx, &byte);
        if(res) {
            return res;
        }

        len++;
        if(byte == '\0') {
            break;
        }
    }

    if(term_out) {
        acpi_ctx_restore(ctx, &chk);

        char *buffer = kmalloc(len);
        if(buffer == NULL) {
            return -ENOMEM;
        }

        res = acpi_ctx_read(ctx, (uint8_t*)buffer, len);
        if(res) {
            kfree(buffer);
            return res;
        }

        buffer[len-1] = '\0';

        *term_out = acpi_create_string_term(buffer);
        if(*term_out == NULL) {
            kfree(buffer);
            return -ENOMEM;
        }

        kfree(buffer);
    }

    return 0;
}

