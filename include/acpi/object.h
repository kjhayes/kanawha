#ifndef __KANAWHA__ACPI_OBJECT_H__
#define __KANAWHA__ACPI_OBJECT_H__

#include <kanawha/types.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>

#define ACPI_OBJ_TYPE_XLIST(X, ...)\
X(UNINITIALIZED,    ##__VA_ARGS__)\
X(BUFFER,           ##__VA_ARGS__)\
X(BUFFER_FIELD,     ##__VA_ARGS__)\
X(DEBUG_OBJ,        ##__VA_ARGS__)\
X(DEVICE,           ##__VA_ARGS__)\
X(EVENT,            ##__VA_ARGS__)\
X(FIELD_UNIT,       ##__VA_ARGS__)\
X(INTEGER,          ##__VA_ARGS__)\
X(CONST_INTEGER,    ##__VA_ARGS__)\
X(METHOD,           ##__VA_ARGS__)\
X(MUTEX,            ##__VA_ARGS__)\
X(OBJ_REF,          ##__VA_ARGS__)\
X(OP_REGION,        ##__VA_ARGS__)\
X(PACKAGE,          ##__VA_ARGS__)\
X(POWER_RESOURCE,   ##__VA_ARGS__)\
X(PROCESSOR,        ##__VA_ARGS__)\
X(RAW_DATA_BUFFER,  ##__VA_ARGS__)\
X(STRING,           ##__VA_ARGS__)\
X(THERMAL_ZONE,     ##__VA_ARGS__)

enum acpi_type {
#define ACPI_OBJ_TYPE_XLIST_DECLARE_ENUM(__NAME)\
    ACPI_TYPE_ ## __NAME,
    ACPI_OBJ_TYPE_XLIST(ACPI_OBJ_TYPE_XLIST_DECLARE_ENUM)
#undef ACPI_OBJ_TYPE_XLIST_DECLARE_ENUM
};

struct acpi_obj
{
    enum acpi_type type;

    spinlock_t ref_lock;
    int refcount;

    union {
        struct {
            size_t size;
            uint8_t *data;
        } buffer; // ACPI_OBJ_TYPE_BUFFER
        struct {
        } buffer_field; // ACPI_OBJ_TYPE_BUFFER_FIELD
        struct {
        } debug_obj; // ACPI_OBJ_TYPE_DEBUG_OBJ
        struct {
        } device; // ACPI_OBJ_TYPE_DEVICE
        struct {
        } event; // ACPI_OBJ_TYPE_EVENT
        struct {
        } field_unit; // ACPI_OBJ_TYPE_FIELD_UNIT
        struct {
            uint64_t value;
        } integer; // ACPI_OBJ_TYPE_INTEGER
        struct {
            uint64_t value;
        } const_integer; // ACPI_OBJ_TYPE_CONST_INTEGER
        struct {
        } method; // ACPI_OBJ_TYPE_METHOD
        struct {
        } mutex; // ACPI_OBJ_TYPE_MUTEX
        struct {
        } obj_ref; // ACPI_OBJ_TYPE_OBJ_REF
        struct {
        } op_region; // ACPI_OBJ_TYPE_OP_REGION
        struct {
        } package; // ACPI_OBJ_TYPE_PACKAGE
        struct {
        } power_resource; // ACPI_OBJ_TYPE_POWER_RESOURCE
        struct {
        } processor; // ACPI_OBJ_TYPE_PROCESSOR
        struct {
        } data_buffer; // ACPI_OBJ_TYPE_RAW_DATA_BUFFER
        struct {
            char *value;
        } string; // ACPI_OBJ_TYPE_STRING
        struct {
        } thermal_zone; // ACPI_OBJ_TYPE_THERMAL_ZONE
    } typed_data;
};

_Static_assert(sizeof(((struct acpi_obj*)0)->typed_data) < 32, "ACPI Object Typed Data is Too Large (This is not a true error, however \"struct acpi_obj\" should be refactored!)");

#ifndef KEEP_ACPI_OBJ_TYPE_XLIST
#undef ACPI_OBJ_TYPE_XLIST
#endif

const char *
acpi_type_to_string(enum acpi_type type);

// Increment refcount of obj
void acpi_obj_get(struct acpi_obj *obj);
// Decrement the refcount of obj (freeing it if this is the last reference)
void acpi_obj_put(struct acpi_obj *obj);

// Returns an obj of type UNINITIALIZED with a single reference
// Or NULL on Failure
struct acpi_obj *
acpi_obj_create_unitialized(void);

// Returns an obj with a single reference
// Or NULL on Failure
struct acpi_obj *
acpi_obj_create_integer(
        uint64_t value);

// Returns an obj with a single reference
// Or NULL on Failure
struct acpi_obj *
acpi_obj_create_const_integer(
        uint64_t value);

// Creates an internal copy of "value"
struct acpi_obj *
acpi_obj_create_string(
        const char *value);

#endif
