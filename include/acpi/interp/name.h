#ifndef __KANAWHA__ACPI_INTERP_NAME_H__
#define __KANAWHA__ACPI_INTERP_NAME_H__

#include <acpi/interp/opcode.h>
#include <acpi/interp/state.h>
#include <acpi/name.h>

int
acpi_interp_name_segment(struct acpi_interp_state *state,
                         struct acpi_name *name_out);

int
acpi_interp_name_string(struct acpi_interp_state *state,
                        struct acpi_path **path_out);

int
acpi_opcode_is_name_string(aml_opcode_t opcode);

#endif
