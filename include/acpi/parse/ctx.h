#ifndef __KANAWHA__ACPI_PARSE_CTX_H__
#define __KANAWHA__ACPI_PARSE_CTX_H__

#include <kanawha/types.h>
#include <kanawha/stree.h>

struct acpi_parse_ctx
{
    void *data_base;
    size_t data_len;

    void *data_head;
};

struct acpi_parse_checkpoint
{
    void *data_head;
};

int
acpi_init_parse_ctx(
        struct acpi_parse_ctx *ctx,
        void *aml_data,
        size_t aml_len); 

int
acpi_destroy_parse_ctx(
        struct acpi_parse_ctx *ctx);

void
acpi_ctx_save(
        struct acpi_parse_ctx *ctx,
        struct acpi_parse_checkpoint *chk);

void
acpi_ctx_restore(
        struct acpi_parse_ctx *ctx,
        struct acpi_parse_checkpoint *chk);

size_t
acpi_ctx_remaining(
        struct acpi_parse_ctx *ctx);

int
acpi_ctx_at_end(
        struct acpi_parse_ctx *ctx);

int
acpi_ctx_pop_u8(
        struct acpi_parse_ctx *ctx,
        uint8_t *out
        );
int
acpi_ctx_pop_u16(
        struct acpi_parse_ctx *ctx,
        uint16_t *out
        );
int
acpi_ctx_pop_u32(
        struct acpi_parse_ctx *ctx,
        uint32_t *out
        );
int
acpi_ctx_pop_u64(
        struct acpi_parse_ctx *ctx,
        uint64_t *out
        );

int
acpi_ctx_read(
        struct acpi_parse_ctx *ctx,
        uint8_t *buffer,
        size_t buflen);

int
acpi_ctx_register_method(
        uint32_t method_name,
        size_t num_args);

int
acpi_ctx_method_arg_count(
        uint32_t method_name,
        size_t *args_out);

#endif
