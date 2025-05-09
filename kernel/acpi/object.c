
#define KEEP_ACPI_OBJ_TYPE_XLIST
#include <acpi/object.h>

#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/stddef.h>

const char *
acpi_type_to_string(enum acpi_type type)
{
    switch(type) {
#define ACPI_TYPE_CASE(__NAME)\
        case ACPI_TYPE_ ## __NAME: return #__NAME;
ACPI_OBJ_TYPE_XLIST(ACPI_TYPE_CASE)
#undef ACPI_TYPE_CASE
        default: return "ERROR-UNKNOWN";
    }
}

// Ignores the refcount of the object and frees its memory no matter what
static int
__acpi_destroy_object(struct acpi_obj *obj)
{
    switch(obj->type) {
        case ACPI_TYPE_UNINITIALIZED:
        case ACPI_TYPE_INTEGER:
        case ACPI_TYPE_CONST_INTEGER:
            break;
        case ACPI_TYPE_STRING:
            kfree(obj->typed_data.string.value);
            break;
        default:
            return -EUNIMPL;
    }

    kfree(obj);

    return 0;
}

struct acpi_obj *
__acpi_obj_create(void)
{
    struct acpi_obj *obj = kmalloc(sizeof(*obj));
    if(obj == NULL) {
        return NULL;
    }

    spinlock_init(&obj->ref_lock);
    obj->refcount = 1;

    return obj;
}

void acpi_obj_get(struct acpi_obj *obj)
{
    spin_lock(&obj->ref_lock);
    DEBUG_ASSERT(obj->refcount > 0);
    obj->refcount++;
    spin_unlock(&obj->ref_lock);
}
void acpi_obj_put(struct acpi_obj *obj)
{
    spin_lock(&obj->ref_lock);
    DEBUG_ASSERT(obj->refcount > 0);
    obj->refcount--;
    if(obj->refcount == 0) {
        __acpi_destroy_object(obj);
    }
    spin_unlock(&obj->ref_lock);
}

struct acpi_obj *
acpi_obj_create_unitialized(void)
{
    struct acpi_obj *obj = __acpi_obj_create();
    if(obj == NULL) {
        return NULL;
    }

    obj->type = ACPI_TYPE_UNINITIALIZED;

    return obj;
}

struct acpi_obj *
acpi_obj_create_integer(uint64_t value)
{
    struct acpi_obj *obj = __acpi_obj_create();
    if(obj == NULL) {
        return NULL;
    }

    obj->type = ACPI_TYPE_INTEGER;
    obj->typed_data.integer.value = value;

    return obj;
}

struct acpi_obj *
acpi_obj_create_const_integer(uint64_t value)
{
    struct acpi_obj *obj = __acpi_obj_create();
    if(obj == NULL) {
        return NULL;
    }

    obj->type = ACPI_TYPE_CONST_INTEGER;
    obj->typed_data.integer.value = value;

    return obj;
}

struct acpi_obj *
acpi_obj_create_string(const char *value)
{
    char *clone = kstrdup(value);
    if(clone == NULL) {
        return NULL;
    }

    struct acpi_obj *obj = __acpi_obj_create();
    if(obj == NULL) {
        kfree(clone);
        return NULL;
    }

    obj->type = ACPI_TYPE_STRING;
    obj->typed_data.string.value = clone;

    return obj;
}

