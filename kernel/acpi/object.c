
#include <acpi/namespace.h>
#include <acpi/object.h>

#include <kanawha/atomic.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/printk.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

struct acpi_obj
{
    atomic_t refcount;

    acpi_obj_type_t type;

    union
    {
        unsigned long integral;
        char *string;

        struct
        {
            void *data;
            size_t len;
        } buffer;

        struct
        {
            struct acpi_obj **objs;
            size_t len;
        } package;

        struct
        {
            irq_lock_t lock;
            unsigned int sync_level : 4;
        } mutex;

        struct
        {
            uint8_t type;
            unsigned long offset;
            unsigned long length;
        } op_region;

        struct
        {
            struct acpi_obj *op_region;
            unsigned long bitlen;
            unsigned long bitoffset;
            acpi_field_unit_access_t access;
            acpi_field_unit_update_rule_t update_rule;
            unsigned int locked : 1;
        } field_unit;

        struct
        {
            struct acpi_obj *buffer;
            size_t bitoffset;
            size_t bitwidth;
        } buffer_field;

        struct
        {
            void *aml_data;
            size_t aml_len;
            unsigned int arg_count : 3;
            unsigned int sync_level : 4;
            unsigned int serialized : 1;
        } method;

        struct
        {
            struct acpi_obj *obj;
        } reference;

        struct
        {
            struct acpi_node *scope;
            struct acpi_path *path;
        } named_reference;

        struct
        {
            uint8_t system_level;
            uint16_t resource_order;
        } power_resource;

    } typedata;
};

static inline void
acpi_obj_destroy(struct acpi_obj *obj)
{
    switch(obj->type)
    {
    case ACPI_OBJ_TYPE_UNINITIALIZED:
    case ACPI_OBJ_TYPE_SCOPE:
    case ACPI_OBJ_TYPE_INTEGER:
    case ACPI_OBJ_TYPE_INTEGER_CONSTANT:
    case ACPI_OBJ_TYPE_OP_REGION:
    case ACPI_OBJ_TYPE_DEVICE:
    case ACPI_OBJ_TYPE_THERMAL_ZONE:
    case ACPI_OBJ_TYPE_POWER_RESOURCE:
        break;
    case ACPI_OBJ_TYPE_STRING:
        if(obj->typedata.string != NULL)
        {
            kfree(obj->typedata.string);
            obj->typedata.string = NULL;
        }
        break;
    case ACPI_OBJ_TYPE_BUFFER:
        if(obj->typedata.buffer.data != NULL)
        {
            kfree(obj->typedata.buffer.data);
            obj->typedata.buffer.data = NULL;
        }
        break;
    case ACPI_OBJ_TYPE_FIELD_UNIT:
        if(obj->typedata.field_unit.op_region != NULL)
        {
            acpi_obj_put(obj->typedata.field_unit.op_region);
            obj->typedata.field_unit.op_region = NULL;
        }
        break;
    case ACPI_OBJ_TYPE_BUFFER_FIELD:
        if(obj->typedata.buffer_field.buffer != NULL)
        {
            acpi_obj_put(obj->typedata.buffer_field.buffer);
            obj->typedata.buffer_field.buffer = NULL;
        }
        break;
    case ACPI_OBJ_TYPE_PACKAGE:
        for(size_t i = 0; i < obj->typedata.package.len; i++)
        {
            struct acpi_obj *inner = obj->typedata.package.objs[i];
            if(inner != NULL)
            {
                acpi_obj_put(inner);
            }
        }
        kfree(obj->typedata.package.objs);
        obj->typedata.package.objs = NULL;
        break;
    case ACPI_OBJ_TYPE_REFERENCE:
        acpi_obj_put(obj->typedata.reference.obj);
        break;
    case ACPI_OBJ_TYPE_NAMED_REFERENCE:
        acpi_path_destroy(obj->typedata.named_reference.path);
        acpi_node_put(obj->typedata.named_reference.scope);
        break;
    default:
        wprintk("acpi_obj_destroy is not implemented for type: %s\n",
                acpi_obj_type_to_string(obj->type));
        break;
    }

    kfree(obj);
}

static inline struct acpi_obj *
acpi_obj_create(void)
{
    struct acpi_obj *obj;
    obj = kmalloc(sizeof(*obj), KM_KERNEL);
    if(obj == NULL)
    {
        return NULL;
    }

    atomic_set_relaxed(&obj->refcount, 1);
    obj->type = ACPI_OBJ_TYPE_UNINITIALIZED;
    memset(&obj->typedata, 0, sizeof(obj->typedata));

    return obj;
}

struct acpi_obj *
acpi_create_uninitialized_obj(void)
{
    return acpi_obj_create();
}

void
acpi_obj_get(struct acpi_obj *obj)
{
    DEBUG_ASSERT(KERNEL_ADDR(obj));
    atomic_fetch_inc(&obj->refcount);
}

void
acpi_obj_put(struct acpi_obj *obj)
{
    DEBUG_ASSERT(KERNEL_ADDR(obj));
    atomic_val_t val = atomic_fetch_dec(&obj->refcount) - 1;
    if(val == 0)
    {
        acpi_obj_destroy(obj);
    }
}

acpi_obj_type_t
acpi_obj_get_type(struct acpi_obj *obj)
{
    return obj->type;
}

const char *
acpi_obj_type_to_string(acpi_obj_type_t type)
{
    switch(type)
    {
#define ACPI_OBJ_TYPE_TO_STRING_CASE(__NAME, ...)                              \
    case ACPI_OBJ_TYPE_##__NAME:                                               \
        return #__NAME;
        ACPI_OBJ_TYPE_XLIST(ACPI_OBJ_TYPE_TO_STRING_CASE)
#undef ACPI_OBJ_TYPE_TO_STRING_CASE
    default:
        return "UNKNOWN";
    }
}

struct acpi_obj *
acpi_create_scope_obj(void)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_SCOPE;
    return obj;
}

struct acpi_obj *
acpi_create_integer_obj(unsigned long initial_value)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_INTEGER;
    obj->typedata.integral = initial_value;

    return obj;
}

struct acpi_obj *
acpi_create_integer_constant_obj(unsigned long value)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_INTEGER_CONSTANT;
    obj->typedata.integral = value;

    return obj;
}

struct acpi_obj *
acpi_create_string_obj(const char *string)
{
    char *dup = kstrdup(string);
    if(dup == NULL)
    {
        return NULL;
    }

    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_STRING;
    obj->typedata.string = dup;

    return obj;
}

const char *
acpi_op_region_type_to_string(acpi_op_region_type_t type)
{
    switch(type)
    {
#define ACPI_OP_REGION_TYPE_TO_STRING_CASE(__NAME, __VAL, __PRETTY, ...)       \
    case ACPI_OP_REGION_TYPE_##__NAME:                                         \
        return #__PRETTY;
        ACPI_OP_REGION_TYPE_XLIST(ACPI_OP_REGION_TYPE_TO_STRING_CASE)
#undef ACPI_OP_REGION_TYPE_TO_STRING_CASE
    default:
        return "OEMDefined";
    }
}

struct acpi_obj *
acpi_create_op_region_obj(acpi_op_region_type_t type,
                          unsigned long offset,
                          unsigned long length)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_OP_REGION;
    obj->typedata.op_region.type = type;
    obj->typedata.op_region.offset = offset;
    obj->typedata.op_region.length = length;

    return obj;
}

const char *
acpi_field_unit_access_to_string(acpi_field_unit_access_t type)
{
    switch(type)
    {
#define ACPI_FIELD_UNIT_ACCESS_TO_STRING_CASE(__NAME, __PRETTY, ...)           \
    case ACPI_FIELD_UNIT_ACCESS_##__NAME:                                      \
        return #__PRETTY;
        ACPI_FIELD_UNIT_ACCESS_XLIST(ACPI_FIELD_UNIT_ACCESS_TO_STRING_CASE)
#undef ACPI_FIELD_UNIT_ACCESS_TO_STRING_CASE
    default:
        return "UndefinedAcc";
    }
}

const char *
acpi_field_unit_update_rule_to_string(acpi_field_unit_update_rule_t type)
{
    switch(type)
    {
#define ACPI_FIELD_UNIT_UPDATE_RULE_TO_STRING_CASE(__NAME, __PRETTY, ...)      \
    case ACPI_FIELD_UNIT_UPDATE_RULE_##__NAME:                                 \
        return #__PRETTY;
        ACPI_FIELD_UNIT_UPDATE_RULE_XLIST(
            ACPI_FIELD_UNIT_UPDATE_RULE_TO_STRING_CASE)
#undef ACPI_FIELD_UNIT_UPDATE_RULE_TO_STRING_CASE
    default:
        return "UpdateUndefined";
    }
}

struct acpi_obj *
acpi_create_field_unit_obj(struct acpi_obj *op_region,
                           unsigned long bitlen,
                           unsigned long bitoffset,
                           acpi_field_unit_access_t access,
                           acpi_field_unit_update_rule_t update_rule,
                           int locked)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_FIELD_UNIT;

    obj->typedata.field_unit.op_region = op_region;
    acpi_obj_get(op_region);

    obj->typedata.field_unit.access = access;
    obj->typedata.field_unit.update_rule = update_rule;
    obj->typedata.field_unit.locked = locked;

    return obj;
}

struct acpi_obj *
acpi_create_method_obj(void *aml_data,
                       size_t aml_len,
                       unsigned int arg_count,
                       unsigned int sync_level,
                       unsigned int serialized)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_METHOD;

    obj->typedata.method.arg_count = arg_count;
    obj->typedata.method.sync_level = sync_level;
    obj->typedata.method.serialized = serialized;
    obj->typedata.method.aml_data = aml_data;
    obj->typedata.method.aml_len = aml_len;

    return obj;
}

struct acpi_obj *
acpi_create_buffer_obj(size_t len, void *initial_data, size_t initial_datalen)
{
    if(initial_datalen > len)
    {
        return NULL;
    }

    void *buffer = kmalloc(len, KM_KERNEL);
    if(buffer == NULL)
    {
        return NULL;
    }

    memcpy(buffer, initial_data, initial_datalen);
    memset(buffer + initial_datalen, 0, len - initial_datalen);

    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        kfree(buffer);
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_BUFFER;
    obj->typedata.buffer.data = buffer;
    obj->typedata.buffer.len = len;

    return obj;
}

struct acpi_obj *
acpi_create_device_obj(void)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_DEVICE;

    return obj;
}

struct acpi_obj *
acpi_create_thermal_zone_obj(void)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_THERMAL_ZONE;

    return obj;
}

struct acpi_obj *
acpi_create_power_resource_obj(uint8_t system_level, uint16_t resource_order)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_POWER_RESOURCE;
    obj->typedata.power_resource.system_level = system_level;
    obj->typedata.power_resource.resource_order = resource_order;

    return obj;
}

struct acpi_obj *
acpi_create_mutex_obj(unsigned int sync_level)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_MUTEX;

    obj->typedata.mutex.sync_level = sync_level;
    irq_lock_init(&obj->typedata.mutex.lock);

    return obj;
}

struct acpi_obj *
acpi_create_named_reference(struct acpi_node *scope, struct acpi_path *path)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    struct acpi_path *path_clone = acpi_path_clone(path);
    if(path_clone == NULL)
    {
        acpi_obj_put(obj);
        return NULL;
    }

    acpi_node_get(scope);

    obj->type = ACPI_OBJ_TYPE_NAMED_REFERENCE;
    obj->typedata.named_reference.path = path_clone;
    obj->typedata.named_reference.scope = scope;

    return obj;
}

struct acpi_obj *
acpi_obj_resolve_implicit_refs(struct acpi_obj *ref)
{
    if(ref->type != ACPI_OBJ_TYPE_NAMED_REFERENCE)
    {
        acpi_obj_get(ref);
        return ref;
    }

    struct acpi_obj *obj =
        acpi_node_get_named_object(ref->typedata.named_reference.scope,
                                   ref->typedata.named_reference.path);
    if(obj == NULL)
    {
        return acpi_create_uninitialized_obj();
    }

    return obj;
}

struct acpi_obj *
acpi_create_buffer_field_obj(struct acpi_obj *buffer,
                             size_t bitoffset,
                             size_t bitwidth)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_BUFFER_FIELD;

    acpi_obj_get(buffer);
    obj->typedata.buffer_field.buffer = buffer;
    obj->typedata.buffer_field.bitoffset = bitoffset;
    obj->typedata.buffer_field.bitwidth = bitwidth;

    return obj;
}

struct acpi_obj *
acpi_create_package_obj(size_t len)
{
    struct acpi_obj **objs =
        kzmalloc(sizeof(struct acpi_obj *) * len, KM_KERNEL);
    if(objs == NULL)
    {
        return NULL;
    }

    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        kfree(objs);
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_PACKAGE;

    obj->typedata.package.len = len;
    obj->typedata.package.objs = objs;

    return obj;
}

struct acpi_obj *
acpi_package_get_obj(struct acpi_obj *package, size_t index)
{
    if(package->type != ACPI_OBJ_TYPE_PACKAGE)
    {
        return NULL;
    }

    if(index >= package->typedata.package.len)
    {
        return NULL;
    }

    struct acpi_obj *obj = package->typedata.package.objs[index];
    if(obj == NULL)
    {
        return acpi_create_uninitialized_obj();
    }
    acpi_obj_get(obj);
    return obj;
}

int
acpi_package_set_obj(struct acpi_obj *package,
                     size_t index,
                     struct acpi_obj *to_insert)
{
    if(package->type != ACPI_OBJ_TYPE_PACKAGE)
    {
        return -EINVAL;
    }

    if(index >= package->typedata.package.len)
    {
        return -ERANGE;
    }

    struct acpi_obj *old_obj = package->typedata.package.objs[index];
    acpi_obj_get(to_insert);
    package->typedata.package.objs[index] = to_insert;
    if(old_obj != NULL)
    {
        acpi_obj_put(old_obj);
    }

    return 0;
}
int
acpi_package_remove_obj(struct acpi_obj *package, size_t index)
{
    if(package->type != ACPI_OBJ_TYPE_PACKAGE)
    {
        return -EINVAL;
    }

    if(index >= package->typedata.package.len)
    {
        return -ERANGE;
    }

    struct acpi_obj *old_obj = package->typedata.package.objs[index];
    package->typedata.package.objs[index] = NULL;
    if(old_obj != NULL)
    {
        acpi_obj_put(old_obj);
    }

    return 0;
}

struct acpi_obj *
acpi_create_reference_obj(struct acpi_obj *referenced)
{
    struct acpi_obj *obj = acpi_obj_create();
    if(obj == NULL)
    {
        return NULL;
    }

    obj->type = ACPI_OBJ_TYPE_REFERENCE;

    acpi_obj_get(referenced);
    obj->typedata.reference.obj = referenced;

    return obj;
}

struct acpi_obj *
acpi_obj_clone(struct acpi_obj *obj)
{
    switch(obj->type)
    {
    case ACPI_OBJ_TYPE_INTEGER:
    case ACPI_OBJ_TYPE_INTEGER_CONSTANT:
        return acpi_create_integer_obj(obj->typedata.integral);
    case ACPI_OBJ_TYPE_STRING:
        return acpi_create_string_obj(obj->typedata.string);
    case ACPI_OBJ_TYPE_BUFFER:
        return acpi_create_buffer_obj(obj->typedata.buffer.len,
                                      obj->typedata.buffer.data,
                                      obj->typedata.buffer.len);
    case ACPI_OBJ_TYPE_PACKAGE:
    {
        struct acpi_obj *package =
            acpi_create_package_obj(obj->typedata.package.len);
        for(size_t i = 0; i < obj->typedata.package.len; i++)
        {
            struct acpi_obj *inner = obj->typedata.package.objs[i];
            if(inner != NULL)
            {
                package->typedata.package.objs[i] = acpi_obj_clone(inner);
            }
        }
        return package;
    }
    case ACPI_OBJ_TYPE_REFERENCE:
        return acpi_create_reference_obj(obj->typedata.reference.obj);
    default:
        wprintk("acpi_obj_clone: Unimplemented for type %s\n",
                acpi_obj_type_to_string(obj->type));
        return NULL;
    }
}

struct acpi_obj *
acpi_obj_data_ref_obj(struct acpi_obj *_obj)
{
    struct acpi_obj *ret;
    struct acpi_obj *obj = acpi_obj_resolve_implicit_refs(_obj);
    if(obj->type == ACPI_OBJ_TYPE_UNINITIALIZED)
    {
        // We could not fully resolve this object yet,
        // leave it as a named reference and assume it will not
        // be a ComputationalData object.
        acpi_obj_put(obj);
        obj = _obj;
        acpi_obj_get(obj);
    }

    switch(obj->type)
    {
    case ACPI_OBJ_TYPE_INTEGER:
    case ACPI_OBJ_TYPE_INTEGER_CONSTANT:
    case ACPI_OBJ_TYPE_STRING:
    case ACPI_OBJ_TYPE_BUFFER:
    case ACPI_OBJ_TYPE_BUFFER_FIELD:
    case ACPI_OBJ_TYPE_FIELD_UNIT:
    case ACPI_OBJ_TYPE_PACKAGE:
    case ACPI_OBJ_TYPE_REFERENCE:
        ret = acpi_obj_clone(obj);
        acpi_obj_put(obj);
        return ret;
    case ACPI_OBJ_TYPE_UNINITIALIZED:
    case ACPI_OBJ_TYPE_SCOPE:
        return NULL;
    default:
        ret = acpi_create_reference_obj(obj);
        acpi_obj_put(obj);
        return ret;
    }
}

int
acpi_obj_get_integral_value(struct acpi_obj *_obj, unsigned long *value)
{
    struct acpi_obj *obj = acpi_obj_resolve_implicit_refs(_obj);
    switch(obj->type)
    {
    case ACPI_OBJ_TYPE_INTEGER:
    case ACPI_OBJ_TYPE_INTEGER_CONSTANT:
        *value = obj->typedata.integral;
        acpi_obj_put(obj);
        return 0;
    case ACPI_OBJ_TYPE_BUFFER:
    case ACPI_OBJ_TYPE_BUFFER_FIELD:
    case ACPI_OBJ_TYPE_STRING:
    case ACPI_OBJ_TYPE_FIELD_UNIT:
        acpi_obj_put(obj);
        return -EUNIMPL;
    default:
        acpi_obj_put(obj);
        return -EINVAL;
    }
}

void
acpi_obj_dump(printk_f *printer, struct acpi_obj *obj)
{
    int print_type;
    switch(obj->type)
    {
    case ACPI_OBJ_TYPE_NAMED_REFERENCE:
    case ACPI_OBJ_TYPE_STRING:
    case ACPI_OBJ_TYPE_INTEGER:
    case ACPI_OBJ_TYPE_INTEGER_CONSTANT:
        print_type = 0;
        break;
    default:
        print_type = 1;
        break;
    }

    if(print_type)
    {
        (*printer)("%s(", acpi_obj_type_to_string(obj->type));
    }

    switch(obj->type)
    {
    case ACPI_OBJ_TYPE_INTEGER:
    case ACPI_OBJ_TYPE_INTEGER_CONSTANT:
        (*printer)("0x%lx", obj->typedata.integral);
        break;
    case ACPI_OBJ_TYPE_STRING:
        (*printer)("\"%s\"", obj->typedata.string);
        break;
    case ACPI_OBJ_TYPE_OP_REGION:
        (*printer)("%s,Offset=0x%lx,Length=0x%lx",
                   acpi_op_region_type_to_string(obj->typedata.op_region.type),
                   (ul_t)obj->typedata.op_region.offset,
                   (ul_t)obj->typedata.op_region.length);
        break;
    case ACPI_OBJ_TYPE_FIELD_UNIT:
        (*printer)(
            "Bits=0x%lx,Offset=0x%lx,%s,%s,%s,OpRegion=",
            (ul_t)obj->typedata.field_unit.bitlen,
            (ul_t)obj->typedata.field_unit.bitoffset,
            acpi_field_unit_access_to_string(obj->typedata.field_unit.access),
            acpi_field_unit_update_rule_to_string(
                obj->typedata.field_unit.update_rule),
            obj->typedata.field_unit.locked ? "Locked" : "Unlocked");
        acpi_obj_dump(printer, obj->typedata.field_unit.op_region);
        break;
    case ACPI_OBJ_TYPE_BUFFER_FIELD:
        (*printer)("Offset=0x%lx,Width=0x%lx",
                   (ul_t)obj->typedata.buffer_field.bitoffset,
                   (ul_t)obj->typedata.buffer_field.bitwidth);
        break;
    case ACPI_OBJ_TYPE_METHOD:
        (*printer)("Arg-Count=%u,Sync-Level=0x%x,%s",
                   (u_t)obj->typedata.method.arg_count,
                   (u_t)obj->typedata.method.sync_level,
                   obj->typedata.method.serialized ? "Serialized"
                                                   : "Unserialized");
        break;
    case ACPI_OBJ_TYPE_BUFFER:
        (*printer)("Length=0x%lx", (ul_t)obj->typedata.buffer.len);
        break;
    case ACPI_OBJ_TYPE_MUTEX:
        (*printer)("Sync-Level=0x%x", (u_t)obj->typedata.mutex.sync_level);
        break;
    case ACPI_OBJ_TYPE_PACKAGE:
        for(size_t i = 0; i < obj->typedata.package.len; i++)
        {
            struct acpi_obj *inner = obj->typedata.package.objs[i];
            if(i > 0)
            {
                (*printer)(",");
            }
            if(inner == NULL)
            {
                (*printer)("NULL");
            }
            else
            {
                acpi_obj_dump(printer, inner);
            }
        }
        break;
    case ACPI_OBJ_TYPE_REFERENCE:
        switch(obj->typedata.reference.obj->type)
        {
        case ACPI_OBJ_TYPE_NAMED_REFERENCE:
            acpi_obj_dump(printer, obj->typedata.reference.obj);
            break;
        default:
            (*printer)(
                acpi_obj_type_to_string(obj->typedata.reference.obj->type));
            break;
        }
        break;
    case ACPI_OBJ_TYPE_NAMED_REFERENCE:
    {
        struct acpi_path *path =
            acpi_path_create_absolute(obj->typedata.named_reference.scope,
                                      obj->typedata.named_reference.path);
        if(path == NULL)
        {
            (*printer)("INVALID-NAMED-REFERENCE");
        }
        else
        {
            acpi_dump_path(printer, path);
            acpi_path_destroy(path);
        }
    }
    break;
    default:
        break;
    }

    if(print_type)
    {
        (*printer)(")");
    }
}
