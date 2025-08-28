#ifndef __KANAWHA__ACPI_OBJECT_H__
#define __KANAWHA__ACPI_OBJECT_H__

#include <kanawha/types.h>
#include <kanawha/printk.h>

struct acpi_obj;
struct acpi_node;
struct acpi_path;

#define ACPI_OBJ_TYPE_XLIST(X,...)\
X(UNINITIALIZED,     ##__VA_ARGS__)\
X(BUFFER,            ##__VA_ARGS__)\
X(BUFFER_FIELD,      ##__VA_ARGS__)\
X(DEBUG,             ##__VA_ARGS__)\
X(DEVICE,            ##__VA_ARGS__)\
X(EVENT,             ##__VA_ARGS__)\
X(FIELD_UNIT,        ##__VA_ARGS__)\
X(INTEGER,           ##__VA_ARGS__)\
X(INTEGER_CONSTANT,  ##__VA_ARGS__)\
X(METHOD,            ##__VA_ARGS__)\
X(MUTEX,             ##__VA_ARGS__)\
X(REFERENCE,         ##__VA_ARGS__)\
X(OP_REGION,         ##__VA_ARGS__)\
X(PACKAGE,           ##__VA_ARGS__)\
X(STRING,            ##__VA_ARGS__)\
X(POWER_RESOURCE,    ##__VA_ARGS__)\
X(RAW_DATA_BUFFER,   ##__VA_ARGS__)\
X(THERMAL_ZONE,      ##__VA_ARGS__)\
/* These are "psuedo-types" (not in the spec) */ \
X(SCOPE,             ##__VA_ARGS__)\
X(NAMED_REFERENCE,   ##__VA_ARGS__)\

typedef enum acpi_obj_type {
#define ACPI_OBJ_TYPE_XLIST_ENUM(__NAME, ...)\
    ACPI_OBJ_TYPE_ ## __NAME,
ACPI_OBJ_TYPE_XLIST(ACPI_OBJ_TYPE_XLIST_ENUM)
#undef ACPI_OBJ_TYPE_XLIST_ENUM
} acpi_obj_type_t;

struct acpi_obj *
acpi_create_uninitialized_obj(void);

void
acpi_obj_get(struct acpi_obj *obj);

void
acpi_obj_put(struct acpi_obj *obj);

acpi_obj_type_t
acpi_obj_get_type(
	struct acpi_obj *obj);

const char *
acpi_obj_type_to_string(
	acpi_obj_type_t type);

// Object Creation

struct acpi_obj *
acpi_create_scope_obj(void);

struct acpi_obj *
acpi_create_integer_obj(
	unsigned long initial_value);

struct acpi_obj *
acpi_create_integer_constant_obj(
	unsigned long value);

struct acpi_obj *
acpi_create_string_obj(
	const char *string);

#define ACPI_OP_REGION_TYPE_XLIST(X,...)\
X(SYSTEM_MEMORY,       0x00,  SystemMemory,      ##__VA_ARGS__)\
X(SYSTEM_IO,           0x01,  SystemIO,          ##__VA_ARGS__)\
X(PCI_CONFIG,          0x02,  PCI_Config,        ##__VA_ARGS__)\
X(EMBEDDED_CTRL,       0x03,  EmbeddedControl,   ##__VA_ARGS__)\
X(SMBUS,               0x04,  SMBus,             ##__VA_ARGS__)\
X(SYSTEM_CMOS,         0x05,  SystemCMOS,        ##__VA_ARGS__)\
X(PCI_BAR,             0x06,  PciBarTarget,      ##__VA_ARGS__)\
X(IPMI,                0x07,  IPMI,              ##__VA_ARGS__)\
X(GPIO,                0x08,  GeneralPurposeIO,  ##__VA_ARGS__)\
X(GENERIC_SERIAL_BUS,  0x09,  GenericSerialBus,  ##__VA_ARGS__)\
X(PCC,                 0x0A,  PCC,               ##__VA_ARGS__)

typedef enum acpi_op_region_type {

#define ACPI_OP_REGION_TYPE_ENUM(__NAME, __VAL, ...)\
    ACPI_OP_REGION_TYPE_ ## __NAME = __VAL,
ACPI_OP_REGION_TYPE_XLIST(ACPI_OP_REGION_TYPE_ENUM)
#undef ACPI_OP_REGION_TYPE_ENUM

} acpi_op_region_type_t;

const char *
acpi_op_region_type_to_string(
	acpi_op_region_type_t type);

struct acpi_obj *
acpi_create_op_region_obj(
	acpi_op_region_type_t type,
	unsigned long offset,
	unsigned long length);

#define ACPI_FIELD_UNIT_ACCESS_XLIST(X,...)\
X(ANY,    AnyAcc,    ##__VA_ARGS__)\
X(BYTE,   ByteAcc,   ##__VA_ARGS__)\
X(WORD,   WordAcc,   ##__VA_ARGS__)\
X(DWORD,  DWordAcc,  ##__VA_ARGS__)\
X(QWORD,  QWordAcc,  ##__VA_ARGS__)\
X(BUFFER, BufferAcc, ##__VA_ARGS__)\

typedef enum acpi_field_unit_access {

#define ACPI_FIELD_UNIT_ACCESS_ENUM(__NAME, ...)\
    ACPI_FIELD_UNIT_ACCESS_ ## __NAME,
ACPI_FIELD_UNIT_ACCESS_XLIST(ACPI_FIELD_UNIT_ACCESS_ENUM)
#undef ACPI_FIELD_UNIT_ACCESS_ENUM

} acpi_field_unit_access_t;

const char *
acpi_field_unit_access_to_string(
	acpi_field_unit_access_t access);

#define ACPI_FIELD_UNIT_UPDATE_RULE_XLIST(X,...)\
X(PRESERVE,    UpdatePreserve,   ##__VA_ARGS__)\
X(WRITE_ZEROS, UpdateWriteZeros, ##__VA_ARGS__)\
X(WRITE_ONES,  UpdateWriteOnes,  ##__VA_ARGS__)\

typedef enum acpi_field_unit_update_rule {

#define ACPI_FIELD_UNIT_UPDATE_RULE_ENUM(__NAME, ...)\
    ACPI_FIELD_UNIT_UPDATE_RULE_ ## __NAME,
ACPI_FIELD_UNIT_UPDATE_RULE_XLIST(ACPI_FIELD_UNIT_UPDATE_RULE_ENUM)
#undef ACPI_FIELD_UNIT_UPDATE_RULE_ENUM

} acpi_field_unit_update_rule_t;

const char *
acpi_field_unit_update_rule_to_string(
	acpi_field_unit_update_rule_t access);

struct acpi_obj *
acpi_create_field_unit_obj(
	struct acpi_obj *op_region,
	unsigned long bitlen,
	unsigned long bitoffset,
	acpi_field_unit_access_t access,
	acpi_field_unit_update_rule_t update_rule,
	int locked
	);

struct acpi_obj *
acpi_create_method_obj(
        void *aml_data,
	size_t aml_len,
	unsigned int arg_count,
	unsigned int sync_level,
	unsigned int serialized
	);

struct acpi_obj *
acpi_create_buffer_obj(
	size_t len,
	void *initial_data,
	size_t initial_datalen);

struct acpi_obj *
acpi_create_device_obj(void);

struct acpi_obj *
acpi_create_thermal_zone_obj(void);

struct acpi_obj *
acpi_create_power_resource_obj(
	uint8_t system_level,
	uint16_t resource_order);

struct acpi_obj *
acpi_create_mutex_obj(
	unsigned int sync_level);

struct acpi_obj *
acpi_create_named_reference(
	struct acpi_node *scope,
	struct acpi_path *path);

struct acpi_obj *
acpi_obj_resolve_implicit_refs(
	struct acpi_obj *obj);

struct acpi_obj *
acpi_create_buffer_field_obj(
	struct acpi_obj *buffer,
	size_t bitoffset,
	size_t bitwidth);

struct acpi_obj *
acpi_create_package_obj(
	size_t entries);

// Package Insert/Retreive/Remove
struct acpi_obj *
acpi_package_get_obj(
	struct acpi_obj *package,
	size_t index);
int
acpi_package_set_obj(
	struct acpi_obj *package,
	size_t index,
	struct acpi_obj *to_insert);
int
acpi_package_remove_obj(
	struct acpi_obj *package,
	size_t index);

// Follows DataRefObj from the AML spec,
// if the object is ComputationalData, then it
// will create a clone of the object, otherwise
// it will wrap it in a reference.
struct acpi_obj *
acpi_obj_data_ref_obj(struct acpi_obj *obj);

// May perform an implicit conversion internally
int
acpi_obj_get_integral_value(
	struct acpi_obj *obj,
	unsigned long *value);

// Single line printer
void
acpi_obj_dump(
	printk_f *printer,
	struct acpi_obj *obj);

#endif
