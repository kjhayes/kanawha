#ifndef __KANAWHA__ACPI_TERMS_LOCAL_OBJ_H__
#define __KANAWHA__ACPI_TERMS_LOCAL_OBJ_H__

#include <acpi/term.h>

struct acpi_term *
acpi_create_arg_term(size_t index);

struct acpi_term *
acpi_create_local_term(size_t index);

#endif
