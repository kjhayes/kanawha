
#include <acpi/parse/ctx.h>

#include <kanawha/types.h>
#include <kanawha/assert.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>

int
acpi_init_parse_ctx(
        struct acpi_parse_ctx *ctx,
        void *data,
        size_t len)
{
    ctx->data_base = data;
    ctx->data_len = len;

    ctx->data_head = ctx->data_base;

    return 0;
}

void
acpi_ctx_save(
        struct acpi_parse_ctx *ctx,
        struct acpi_parse_checkpoint *chk)
{
    chk->data_head = ctx->data_head;
}

void
acpi_ctx_restore(
        struct acpi_parse_ctx *ctx,
        struct acpi_parse_checkpoint *chk)
{
    ctx->data_head = chk->data_head;
}

size_t
acpi_ctx_remaining(
        struct acpi_parse_ctx *ctx)
{
    DEBUG_ASSERT(ctx->data_head <= (ctx->data_base + ctx->data_len));
    return (ctx->data_base + ctx->data_len) - ctx->data_head;
}

int
acpi_ctx_at_end(struct acpi_parse_ctx *ctx)
{
    return ctx->data_head >= (ctx->data_base + ctx->data_len);
}

int
acpi_ctx_pop_u8(
        struct acpi_parse_ctx *ctx,
        uint8_t *out
        )
{
    if(acpi_ctx_remaining(ctx) < 1) {
        return -ENXIO;
    }
    uint8_t val = *(uint8_t*)ctx->data_head;
    ctx->data_head++;
    if(out != NULL) {
        *out = val;
    }
    return 0;
}
int
acpi_ctx_pop_u16(
        struct acpi_parse_ctx *ctx,
        uint16_t *out
        )
{
    if(acpi_ctx_remaining(ctx) < 2) {
        return -ENXIO;
    }
    uint16_t val = *(uint16_t*)ctx->data_head;
    ctx->data_head += 2;
    if(out != NULL) {
        *out = val;
    }
    return 0;
}
int
acpi_ctx_pop_u32(
        struct acpi_parse_ctx *ctx,
        uint32_t *out
        )
{
    if(acpi_ctx_remaining(ctx) < 4) {
        return -ENXIO;
    }
    uint32_t val = *(uint32_t*)ctx->data_head;
    ctx->data_head += 4;
    if(out != NULL) {
        *out = val;
    }
    return 0;
}
int
acpi_ctx_pop_u64(
        struct acpi_parse_ctx *ctx,
        uint64_t *out
        )
{
    if(acpi_ctx_remaining(ctx) < 8) {
        return -ENXIO;
    }
    uint64_t val = *(uint64_t*)ctx->data_head;
    ctx->data_head += 8;
    if(out != NULL) {
        *out = val;
    }
    return 0;
}

int
acpi_ctx_read(
        struct acpi_parse_ctx *ctx,
        uint8_t *buffer,
        size_t buflen)
{
    if(acpi_ctx_remaining(ctx) < buflen) {
        return -ENXIO;
    }

    memcpy(buffer, ctx->data_head, buflen);
    ctx->data_head += buflen;

    return 0;
}

