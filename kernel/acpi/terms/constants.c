
#include <acpi/terms/constants.h>
#include <acpi/term.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

#include <acpi/object.h>

static int
__destroy_constant_term(struct acpi_term *term)
{
    kfree(term);
    return 0;
}

static struct acpi_term *
__create_constant_term(void)
{
    struct acpi_term *term;
    term = kzmalloc(sizeof(struct acpi_term), KM_KERNEL);
    if(term == NULL) {
        return term;
    }
    term->destroy = __destroy_constant_term;
    return term;
}

static int
__eval_integer_constant(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj_out)
{
    if(obj_out != NULL) {
        *obj_out = acpi_obj_create_const_integer(term->priv.value);
        if(*obj_out == NULL) {
            return -ENOMEM;
        }
    }
    return 0;
}

static struct acpi_term *
__create_integer_constant(uint64_t value)
{
    struct acpi_term *term = __create_constant_term();
    if(term == NULL) {
        return NULL;
    }
    term->eval = __eval_integer_constant;
    term->priv.value = value;
    return term;
}

static int
__dump_byte_const(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("BYTE-CONST(0x%llx)\n", term->priv.value);
    return 0;
}

static int
__dump_word_const(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("WORD-CONST(0x%llx)\n", term->priv.value);
    return 0;
}

static int
__dump_dword_const(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("DWORD-CONST(0x%llx)\n", term->priv.value);
    return 0;
}

static int
__dump_qword_const(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("QWORD-CONST(0x%llx)\n", term->priv.value);
    return 0;
}

struct acpi_term *
acpi_create_byte_const_term(uint8_t value)
{
    struct acpi_term *term = __create_integer_constant((uint64_t)value);
    if(term != NULL) {
        term->dump = __dump_byte_const;
    }
    return term;
}
struct acpi_term *
acpi_create_word_const_term(uint16_t value)
{
    struct acpi_term *term = __create_integer_constant((uint64_t)value);
    if(term != NULL) {
        term->dump = __dump_word_const;
    }
    return term;

}
struct acpi_term *
acpi_create_dword_const_term(uint32_t value)
{
    struct acpi_term *term = __create_integer_constant((uint64_t)value);
    if(term != NULL) {
        term->dump = __dump_dword_const;
    }
    return term;

}
struct acpi_term *
acpi_create_qword_const_term(uint64_t value)
{
    struct acpi_term *term = __create_integer_constant((uint64_t)value);
    if(term != NULL) {
        term->dump = __dump_qword_const;
    }
    return term;

}

static int
__dump_zero(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("ZERO\n");
    return 0;
}

static int
__dump_one(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("ONE\n");
    return 0;
}

static int
__dump_ones(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("ONES\n");
    return 0;
}

struct acpi_term *
acpi_create_zero_term(void)
{
    struct acpi_term *term = __create_integer_constant((uint64_t)0);
    if(term) {
        term->dump = __dump_zero;
    }
    return term;
}
struct acpi_term *
acpi_create_one_term(void)
{
    struct acpi_term *term = __create_integer_constant((uint64_t)1);
    if(term) {
        term->dump = __dump_one;
    }
    return term;
}
struct acpi_term *
acpi_create_ones_term(void)
{
    struct acpi_term *term = __create_integer_constant((uint64_t)-1);
    if(term) {
        term->dump = __dump_ones;
    }
    return term;
}

static int
__eval_revision_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj)
{
    return -EUNIMPL;
}

static int
__dump_revision(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("REVISION\n");
    return 0;
}

struct acpi_term *
acpi_create_revision_term(void)
{
    struct acpi_term *term = __create_constant_term();
    if(term == NULL) {
        return NULL;
    }

    term->eval = __eval_revision_term;
    term->dump = __dump_revision;

    return term;
}

static int
__destroy_string_constant_term(struct acpi_term *term)
{
    kfree(term->priv.ptr);
    kfree(term);
    return 0;
}

static int
__eval_string_constant_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj)
{
    if(obj == NULL) {
        return 0;
    }

    *obj = acpi_obj_create_string(term->priv.ptr);
    if(*obj == NULL) {
        return -ENOMEM;
    }

    return 0;
}

static int
__dump_string_constant_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("STRING(\"%s\")\n",
            (char*)term->priv.ptr);
    return 0;
}

struct acpi_term *
acpi_create_string_term(const char *value)
{
    struct acpi_term *term = kzmalloc(sizeof(struct acpi_term), KM_KERNEL);
    if(term == NULL) {
        return NULL;
    }

    term->priv.ptr = kstrdup(value);
    if(term->priv.ptr == NULL) {
        kfree(term);
        return NULL;
    }

    term->destroy = __destroy_string_constant_term;
    term->eval = __eval_string_constant_term;
    term->dump = __dump_string_constant_term;

    return term;
}

