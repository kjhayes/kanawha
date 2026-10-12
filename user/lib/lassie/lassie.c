
#include <lassie/lassie.h>
#include <lassie/list.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct lassie {
    enum {
        LASSIE_TYPE_OBJ,
        LASSIE_TYPE_ARRAY,
        LASSIE_TYPE_NUMBER,
        LASSIE_TYPE_STRING,
        LASSIE_TYPE_BOOLEAN,
        LASSIE_TYPE_NULL,
    } type;

    struct lassie * parent;

    list_node_t array_node;
};

struct lassie_field {
    char *key;
    struct lassie *value;
    list_node_t obj_node;
};

struct lassie_obj {
    struct lassie lassie;
    list_t fields;
};

struct lassie_array {
    struct lassie lassie;
    list_t entries;
};

struct lassie_number {
    struct lassie lassie;
    long value;
};

struct lassie_string {
    struct lassie lassie;
    char *value;
};

struct lassie_boolean {
    struct lassie lassie;
    unsigned value : 1;
};

struct lassie_null {
    struct lassie lassie;
};

DEFINE_CUSTOM_LIST(
        _lassie_obj_fields,
        struct lassie_obj,
        fields,
        struct lassie_field,
        obj_node);

DEFINE_CUSTOM_LIST(
        _lassie_array_entries,
        struct lassie_array,
        entries,
        struct lassie,
        array_node);

struct lassie * lassie_from_obj(struct lassie_obj *obj)
{
    return &obj->lassie;
}
struct lassie * lassie_from_array(struct lassie_array *array)
{
    return &array->lassie;
}
struct lassie * lassie_from_number(struct lassie_number *number)
{
    return &number->lassie;
}
struct lassie * lassie_from_string(struct lassie_string *string)
{
    return &string->lassie;
}
struct lassie * lassie_from_boolean(struct lassie_boolean *boolean)
{
    return &boolean->lassie;
}
struct lassie * lassie_from_null(struct lassie_null *null)
{
    return &null->lassie;
}

struct lassie_obj * lassie_to_obj(struct lassie *lassie)
{
    if(lassie == NULL || lassie->type != LASSIE_TYPE_OBJ) {
        return NULL;
    }
    return container_of(lassie, struct lassie_obj, lassie);
}
struct lassie_array * lassie_to_array(struct lassie *lassie)
{
    if(lassie == NULL || lassie->type != LASSIE_TYPE_ARRAY) {
        return NULL;
    }
    return container_of(lassie, struct lassie_array, lassie);
}
struct lassie_number * lassie_to_number(struct lassie *lassie)
{
    if(lassie == NULL || lassie->type != LASSIE_TYPE_NUMBER) {
        return NULL;
    }
    return container_of(lassie, struct lassie_number, lassie);
}
struct lassie_string * lassie_to_string(struct lassie *lassie)
{
    if(lassie == NULL || lassie->type != LASSIE_TYPE_STRING) {
        return NULL;
    }
    return container_of(lassie, struct lassie_string, lassie);
}
struct lassie_boolean * lassie_to_boolean(struct lassie *lassie)
{
    if(lassie == NULL || lassie->type != LASSIE_TYPE_BOOLEAN) {
        return NULL;
    }
    return container_of(lassie, struct lassie_boolean, lassie);
}
struct lassie_null * lassie_to_null(struct lassie *lassie)
{
    if(lassie == NULL || lassie->type != LASSIE_TYPE_NULL) {
        return NULL;
    }
    return container_of(lassie, struct lassie_null, lassie);
}

static inline int
_lassie_init(struct lassie *lassie)
{
    return 0;
}
static inline void
_lassie_deinit(struct lassie *lassie)
{
}

struct lassie_obj *
lassie_create_obj(void)
{
    int res;
    struct lassie_obj *obj = malloc(sizeof(*obj));
    if(obj == NULL) {
        return NULL;
    }
    obj->lassie.type = LASSIE_TYPE_OBJ;
    res = _lassie_init(lassie_from_obj(obj));
    if(res) {
        free(obj);
        return NULL;
    }
    _lassie_obj_fields_init(obj);
    return obj;
}
static struct lassie_field *
_lassie_obj_get_field(
        struct lassie_obj *obj,
        const char *key)
{
    int res;
    struct lassie_field *f;
    f = _lassie_obj_fields_begin(obj);
    while(f) {
        if(strcmp(f->key, key) == 0) {
            return f;
        }
        f = _lassie_obj_fields_next(obj, f);
    }
    return NULL;
}
static struct lassie_field *
_lassie_obj_get_or_create_field(
        struct lassie_obj *obj,
        const char *key)
{
    int res;
    struct lassie_field *f;
    f = _lassie_obj_get_field(obj, key);
    if(f != NULL) {
        return f;
    }

    f = malloc(sizeof(struct lassie_field));
    if(f == NULL) {
        return NULL;
    }
    f->key = strdup(key);
    if(f->key == NULL) {
        free(f);
        return NULL;
    }
    f->value = NULL;
    _lassie_obj_fields_push_tail(obj, f);
    return f;
}
static void
_lassie_obj_destroy_field(
        struct lassie_obj *obj,
        struct lassie_field *f)
{
    int res;
    _lassie_obj_fields_remove(obj, f);
    if(f->value) {
        lassie_destroy(f->value);
    }
    free(f->key);
    free(f);
}

struct lassie_array *
lassie_create_array(void)
{
    int res;
    struct lassie_array *array = malloc(sizeof(*array));
    if(array == NULL) {
        return NULL;
    }
    array->lassie.type = LASSIE_TYPE_ARRAY;
    res = _lassie_init(lassie_from_array(array));
    if(res) {
        free(array);
        return NULL;
    }
    _lassie_array_entries_init(array);
    return array;
}
struct lassie_number *
lassie_create_number(long value)
{
    int res;
    struct lassie_number *number = malloc(sizeof(*number));
    if(number == NULL) {
        return NULL;
    }
    number->lassie.type = LASSIE_TYPE_NUMBER;
    res = _lassie_init(lassie_from_number(number));
    if(res) {
        free(number);
        return NULL;
    }
    number->value = value;
    return number;
}
struct lassie_string *
lassie_create_string(const char *value)
{
    int res;
    char *dup = strdup(value);
    if(dup == NULL) {
        return NULL;
    }
    struct lassie_string *string = malloc(sizeof(*string));
    if(string == NULL) {
        free(dup);
        return NULL;
    }
    string->lassie.type = LASSIE_TYPE_STRING;
    res = _lassie_init(lassie_from_string(string));
    if(res) {
        free(dup);
        free(string);
        return NULL;
    }
    string->value = dup;
    return string;
}
struct lassie_boolean *
lassie_create_boolean(unsigned int value)
{
    int res;
    struct lassie_boolean *boolean = malloc(sizeof(*boolean));
    if(boolean == NULL) {
        return NULL;
    }
    boolean->lassie.type = LASSIE_TYPE_BOOLEAN;
    res = _lassie_init(lassie_from_boolean(boolean));
    if(res) {
        free(boolean);
        return NULL;
    }
    boolean->value = value;
    return boolean;
}
struct lassie_null *
lassie_create_null(void)
{
    int res;
    struct lassie_null *null = malloc(sizeof(*null));
    if(null == NULL) {
        return NULL;
    }
    null->lassie.type = LASSIE_TYPE_NULL;
    res = _lassie_init(lassie_from_null(null));
    if(res) {
        free(null);
        return NULL;
    }
    return null;
}

void
lassie_destroy_obj(struct lassie_obj *obj)
{
    _lassie_deinit(lassie_from_obj(obj));
    while(1) {
        struct lassie_field *field;
        field = _lassie_obj_fields_begin(obj);
        if(field == NULL) {
            break;
        }
        _lassie_obj_destroy_field(obj, field);
    }
    free(obj);
}
void
lassie_destroy_array(struct lassie_array *array)
{
    _lassie_deinit(lassie_from_array(array));
    while(1) {
        struct lassie *elem;
        elem = _lassie_array_entries_begin(array);
        if(elem == NULL) {
            break;
        }
        _lassie_array_entries_remove(array, elem);
        lassie_destroy(elem);
    }
    free(array);
}
void
lassie_destroy_number(struct lassie_number *number)
{
    _lassie_deinit(lassie_from_number(number));
    free(number);
}
void
lassie_destroy_string(struct lassie_string *string)
{
    _lassie_deinit(lassie_from_string(string));
    free(string->value);
    free(string);
}
void
lassie_destroy_boolean(struct lassie_boolean *boolean)
{
    _lassie_deinit(lassie_from_boolean(boolean));
    free(boolean);
}
void
lassie_destroy_null(struct lassie_null *null)
{
    _lassie_deinit(lassie_from_null(null));
    free(null);
}

void lassie_destroy(struct lassie *lassie)
{
    switch(lassie->type) {
        case LASSIE_TYPE_OBJ:
            lassie_destroy_obj(lassie_to_obj(lassie));
            break;
        case LASSIE_TYPE_ARRAY:
            lassie_destroy_array(lassie_to_array(lassie));
            break;
        case LASSIE_TYPE_NUMBER:
            lassie_destroy_number(lassie_to_number(lassie));
            break;
        case LASSIE_TYPE_STRING:
            lassie_destroy_string(lassie_to_string(lassie));
            break;
        case LASSIE_TYPE_BOOLEAN:
            lassie_destroy_boolean(lassie_to_boolean(lassie));
            break;
        case LASSIE_TYPE_NULL:
            lassie_destroy_null(lassie_to_null(lassie));
            break;
        default:
            return;
    }
}

// Object Ops
int
lassie_obj_insert(
        struct lassie_obj *obj,
        const char *key,
        struct lassie *value)
{
    struct lassie_field *f;
    f = _lassie_obj_get_field(obj, key);
    if(f != NULL) {
        return -EEXIST;
    }
    f = _lassie_obj_get_or_create_field(obj, key);
    if(f == NULL) {
        return -ENOMEM;
    }
    if(f->value != NULL) {
        return -EEXIST;
    }
    f->value = value;
    return 0;
}
int
lassie_obj_set(
        struct lassie_obj *obj,
        const char *key,
        struct lassie *value)
{
    struct lassie_field *f;
    f = _lassie_obj_get_or_create_field(obj, key);
    if(f == NULL) {
        return -ENOMEM;
    }
    if(f->value) {
        struct lassie *old = f->value;
        f->value = NULL;
        lassie_destroy(old);
    }
    f->value = value;
    return 0;
}
struct lassie *
lassie_obj_get(
        struct lassie_obj *obj,
        const char *key)
{
    struct lassie_field *f;
    f = _lassie_obj_get_field(obj, key);
    if(f == NULL || f->value == NULL) {
        return NULL;
    }
    return f->value;
}
struct lassie *
lassie_obj_drop(
        struct lassie_obj *obj,
        const char *key)
{
    struct lassie_field *f;
    f = _lassie_obj_get_field(obj, key);
    if(f == NULL) {
        return NULL;
    }

    struct lassie *value = f->value;
    f->value = NULL;
    _lassie_obj_destroy_field(obj, f);

    return value;
}

struct lassie_field;

struct lassie_field *
lassie_obj_fields_begin(
        struct lassie_obj *obj)
{
    return _lassie_obj_fields_begin(obj);
}
struct lassie_field *
lassie_obj_fields_next(
        struct lassie_obj *obj,
        struct lassie_field *iter)
{
    return _lassie_obj_fields_next(obj, iter);
}
const char *
lassie_field_key(
        struct lassie_field *f)
{
    return f->key;
}
struct lassie *
lassie_field_value(
        struct lassie_field *f)
{
    return f->value;
}
unsigned long
lassie_obj_fields_length(
        struct lassie_obj *obj)
{
    return _lassie_obj_fields_count(obj);
}

// Array Ops

void
lassie_array_append(
        struct lassie_array *array,
        struct lassie *value)
{
    _lassie_array_entries_push_tail(array, value);
}

struct lassie *
lassie_array_drop(
        struct lassie_array *array,
        unsigned long index)
{
    struct lassie *elem;
    elem = lassie_array_index(array, index);
    if(elem == NULL) {
        return NULL;
    }
    _lassie_array_entries_remove(array, elem);
    return elem;
}

unsigned long
lassie_array_length(
        struct lassie_array *array)
{
    return _lassie_array_entries_count(array);
}

struct lassie *
lassie_array_begin(
        struct lassie_array *array)
{
    return _lassie_array_entries_begin(array);
}
struct lassie *
lassie_array_next(
        struct lassie_array *array,
        struct lassie *iter)
{
    return _lassie_array_entries_next(array, iter);
}
struct lassie *
lassie_array_index(
        struct lassie_array *array,
        unsigned long index)
{
    unsigned long i = 0;
    struct lassie *iter = lassie_array_begin(array);
    while(iter) {
        if(i == index) {
            return iter;
        }
        i++;
        iter = lassie_array_next(array, iter);
    }
    return NULL;
}

// Number Ops

long
lassie_number_get_value(
        struct lassie_number *number)
{
    return number->value;
}
void
lassie_number_set_value(
        struct lassie_number *number,
        long value)
{
    number->value = value;
}

// String Ops

const char *
lassie_string_get_value(
        struct lassie_string *string)
{
    return string->value;
}
int
lassie_string_set_value(
        struct lassie_string *string,
        const char *value)
{
    char *old = string->value;
    char *dup = strdup(value);
    if(dup == NULL) {
        return -ENOMEM;
    }
    string->value = dup;
    free(old);
    return 0;
}

// Boolean Ops

unsigned int
lassie_boolean_get_value(
        struct lassie_boolean *boolean)
{
    return boolean->value;
}
void
lassie_boolean_set_value(
        struct lassie_boolean *boolean,
        unsigned int value)
{
    boolean->value = !!value;
}
