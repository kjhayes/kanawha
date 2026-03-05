
#include <acpi/interp/name.h>
#include <acpi/interp/named_reference.h>
#include <acpi/interp/opcode.h>
#include <acpi/interp/raw.h>
#include <acpi/interp/state.h>
#include <acpi/interp/string.h>
#include <acpi/interp/term_arg.h>
#include <acpi/object.h>

#include <kanawha/errno.h>

int
acpi_interp_term_arg(struct acpi_interp_state *state, struct acpi_obj **obj)
{
    int res;

    aml_opcode_t opcode;
    res = acpi_interp_peek_aml_opcode(state, &opcode);
    if(res)
    {
        return res;
    }

    if(opcode != AML_ZERO_OP && acpi_opcode_is_name_string(opcode))
    {
        struct acpi_obj *named_ref;
        res = acpi_interp_name_string_as_named_reference(state, &named_ref);
        if(res)
        {
            return res;
        }
        struct acpi_obj *resolved = acpi_obj_resolve_implicit_refs(named_ref);
        acpi_obj_put(named_ref);

        if(acpi_obj_get_type(resolved) == ACPI_OBJ_TYPE_METHOD)
        {
            // This is a method invokation.
            wprintk("acpi_interp_term_arg: Method invokation is "
                    "unimplemented!\n");
            acpi_obj_put(resolved);
            return -EUNIMPL;
        }
        else
        {
            *obj = resolved;
            return 0;
        }
    }

    res = acpi_interp_aml_opcode(state, &opcode);
    if(res)
    {
        return res;
    }

    union
    {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    } tmp;

    switch(opcode)
    {
    case AML_BYTE_PREFIX:
        res = acpi_interp_raw_u8(state, &tmp.u8);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Malformed AML_BYTE_PREFIX!\n");
            return res;
        }
        *obj = acpi_create_integer_constant_obj((unsigned long)tmp.u8);
        return 0;
    case AML_WORD_PREFIX:
        res = acpi_interp_raw_u16(state, &tmp.u16);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Malformed AML_WORD_PREFIX!\n");
            return res;
        }
        *obj = acpi_create_integer_constant_obj((unsigned long)tmp.u16);
        return 0;
    case AML_DWORD_PREFIX:
        res = acpi_interp_raw_u32(state, &tmp.u32);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Malformed AML_DWORD_PREFIX!\n");
            return res;
        }
        *obj = acpi_create_integer_constant_obj((unsigned long)tmp.u32);
        return 0;
    case AML_QWORD_PREFIX:
        res = acpi_interp_raw_u64(state, &tmp.u64);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Malformed AML_QWORD_PREFIX!\n");
            return res;
        }
        *obj = acpi_create_integer_constant_obj((unsigned long)tmp.u64);
        return 0;
    case AML_ZERO_OP:
        *obj = acpi_create_integer_constant_obj((unsigned long)0);
        return 0;
    case AML_ONE_OP:
        *obj = acpi_create_integer_constant_obj((unsigned long)1);
        return 0;
    case AML_ONES_OP:
        *obj = acpi_create_integer_constant_obj((unsigned long)(-1));
        return 0;
    case AML_STRING_PREFIX:
        res = acpi_interp_string_after_opcode(state, obj);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Malformed "
                    "AML_STRING_PREFIX!\n");
            return res;
        }
        return 0;
    case AML_BUFFER_OP:
        res = acpi_interp_def_buffer(state, obj);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Failed to interpret DefBuffer! "
                    "(err=%s)\n",
                    errnostr(res));
            return res;
        }
        return 0;
    case AML_PACKAGE_OP:
        res = acpi_interp_def_package(state, obj);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Failed to interpret "
                    "DefPackage! "
                    "(err=%s)\n",
                    errnostr(res));
            return res;
        }
        return 0;
    case AML_VAR_PACKAGE_OP:
        res = acpi_interp_def_varpackage(state, obj);
        if(res)
        {
            wprintk("acpi_interp_term_arg: Failed to interpret "
                    "DefVarPackage! "
                    "(err=%s)\n",
                    errnostr(res));
            return res;
        }
        return 0;
    default:
        wprintk("acpi_interp_term_arg: Cannot handle AML opcode %s\n",
                aml_opcode_to_string(opcode));
        return -EUNIMPL;
    }
}

int
acpi_interp_term_arg_to_integer(struct acpi_interp_state *state,
                                unsigned long *value)
{
    int res;

    struct acpi_obj *obj;
    res = acpi_interp_term_arg(state, &obj);
    if(res)
    {
        return res;
    }

    res = acpi_obj_get_integral_value(obj, value);
    if(res)
    {
        acpi_obj_put(obj);
        return res;
    }

    acpi_obj_put(obj);
    return 0;
}
