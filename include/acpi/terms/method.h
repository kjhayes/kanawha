#ifndef __KANAWHA__ACPI_TERMS_METHOD_H__
#define __KANAWHA__ACPI_TERMS_METHOD_H__

#include <acpi/term.h>
#include <acpi/name.h>

struct acpi_term *
acpi_create_method_invocation_term(
        struct acpi_path *method_name,
        struct acpi_termlist *terms);

#endif
