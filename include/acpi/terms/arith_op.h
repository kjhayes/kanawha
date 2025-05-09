#ifndef __KANAWHA__ACPI_TERMS_ARITH_OP_H__
#define __KANAWHA__ACPI_TERMS_ARITH_OP_H__

#include <acpi/target.h>
#include <acpi/term.h>
#include <acpi/target.h>

enum acpi_unary_arith_op {
    ACPI_UNARY_ARITH_OP_NOT,
};

enum acpi_binary_arith_op {
    ACPI_BINARY_ARITH_OP_ADD,
};

struct acpi_term *
acpi_create_unary_arith_term(
        enum acpi_unary_arith_op op,
        struct acpi_term *arg,
        struct acpi_target *target);

struct acpi_term *
acpi_create_binary_arith_term(
        enum acpi_binary_arith_op op,
        struct acpi_term *arg0,
        struct acpi_term *arg1,
        struct acpi_target *target);

#endif
