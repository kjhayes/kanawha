
#include <acpi/parse/pkg_length.h>
#include <acpi/parse/ctx.h>
#include <kanawha/errno.h>
#include <kanawha/printk.h>

int
acpi_parse_pkg_length(
        struct acpi_parse_ctx *ctx,
        uint32_t *len_out)
{
    int res;

    uint8_t lead_byte;
    res = acpi_ctx_pop_u8(ctx, &lead_byte);
    if(res) {
        return res;
    }

    dprintk("pkg_length lead_byte=0x%x\n", lead_byte);

    uint8_t num_trailing_bytes = (lead_byte>>6) & 0b11;

    if(num_trailing_bytes == 0) {
        if(len_out != NULL) {
            *len_out = (uint32_t)(lead_byte & 0x3F);
        }
        return 0;
    }

    uint32_t value = lead_byte & 0xF;
    for(size_t i = 0; i < num_trailing_bytes; i++) {
        int shift = (i*8) + 4;
        uint8_t trail_byte;
        res = acpi_ctx_pop_u8(ctx, &trail_byte);
        if(res) {
            return res;
        }
        value |= (((uint32_t)trail_byte)<<shift);
    }

    if(len_out != NULL) {
        *len_out = value;
    }
    return 0;
}

int
acpi_segment_package(
        struct acpi_parse_ctx *ctx,
        struct acpi_parse_ctx *inner)
{
    int res;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    uint32_t pkg_length;
    res = acpi_parse_pkg_length(
            ctx,
            &pkg_length);
    if(res) {
        return res;
    }

    acpi_ctx_restore(ctx, &chk);

    if(acpi_ctx_remaining(ctx) >= pkg_length)
    {
        res = acpi_init_parse_ctx(
                inner,
                ctx->data_head,
                pkg_length);
        if(res) {
            return res;
        }

        ctx->data_head += pkg_length;

        res = acpi_parse_pkg_length(inner, &pkg_length);
        if(res) {
            return res;
        }

        return 0;
    }

    return -EINVAL;
}

