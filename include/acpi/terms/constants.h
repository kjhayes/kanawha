#ifndef __KANAWHA__ACPI_TERMS_CONSTANTS_H__
#define __KANAWHA__ACPI_TERMS_CONSTANTS_H__

#include <kanawha/types.h>
#include <acpi/term.h>

struct acpi_term *
acpi_create_byte_const_term(uint8_t value);
struct acpi_term *
acpi_create_word_const_term(uint16_t value);
struct acpi_term *
acpi_create_dword_const_term(uint32_t value);
struct acpi_term *
acpi_create_qword_const_term(uint64_t value);

struct acpi_term *
acpi_create_string_term(const char *value);

struct acpi_term *
acpi_create_zero_term(void);
struct acpi_term *
acpi_create_one_term(void);
struct acpi_term *
acpi_create_ones_term(void);

struct acpi_term *
acpi_create_revision_term(void);

#endif
