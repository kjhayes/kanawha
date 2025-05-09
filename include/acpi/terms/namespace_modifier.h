#ifndef __KANAWHA__ACPI_TERMS_NAMESPACE_MODIFIER_H__
#define __KANAWHA__ACPI_TERMS_NAMESPACE_MODIFIER_H__

#include <acpi/name.h>
#include <acpi/term.h>

// Takes ownership of "path" and "termlist"
struct acpi_term *
acpi_create_scope_term(
        struct acpi_path *path,
        struct acpi_termlist *termlist);

#endif
