#ifndef __LASSIE_LASSIE_H__
#define __LASSIE_LASSIE_H__

struct lassie;
struct lassie_obj;
struct lassie_array;
struct lassie_number;
struct lassie_string;
struct lassie_boolean;
struct lassie_null;

struct lassie * lassie_from_obj(struct lassie_obj *obj);
struct lassie * lassie_from_array(struct lassie_array *array);
struct lassie * lassie_from_number(struct lassie_number *number);
struct lassie * lassie_from_string(struct lassie_string *string);
struct lassie * lassie_from_boolean(struct lassie_boolean *boolean);
struct lassie * lassie_from_null(struct lassie_null *null);

struct lassie_obj * lassie_to_obj(struct lassie *lassie);
struct lassie_array * lassie_to_array(struct lassie *lassie);
struct lassie_number * lassie_to_number(struct lassie *lassie);
struct lassie_string * lassie_to_string(struct lassie *lassie);
struct lassie_boolean * lassie_to_boolean(struct lassie *lassie);
struct lassie_null * lassie_to_null(struct lassie *lassie);

struct lassie_obj * lassie_create_obj(void);
struct lassie_array * lassie_create_array(void);
struct lassie_number * lassie_create_number(long value);
struct lassie_string * lassie_create_string(const char *value);
struct lassie_boolean * lassie_create_boolean(unsigned int value);
struct lassie_null * lassie_create_null(void);

void lassie_destroy_obj(struct lassie_obj *obj);
void lassie_destroy_array(struct lassie_array *array);
void lassie_destroy_number(struct lassie_number *number);
void lassie_destroy_string(struct lassie_string *string);
void lassie_destroy_boolean(struct lassie_boolean *boolean);
void lassie_destroy_null(struct lassie_null *null);

void lassie_destroy(struct lassie *lassie);

// Object
int
lassie_obj_insert(
        struct lassie_obj *obj,
        const char *key,
        struct lassie *value);
int
lassie_obj_set(
        struct lassie_obj *obj,
        const char *key,
        struct lassie *value);
struct lassie *
lassie_obj_get(
        struct lassie_obj *obj,
        const char *key);
struct lassie *
lassie_obj_drop(
        struct lassie_obj *obj,
        const char *key);
struct lassie *
lassie_obj_delete(
        struct lassie_obj *obj,
        const char *key);

struct lassie_field;

struct lassie_field *
lassie_obj_fields_begin(
        struct lassie_obj *);
struct lassie_field *
lassie_obj_fields_next(
        struct lassie_obj *,
        struct lassie_field *);
const char *
lassie_field_key(
        struct lassie_field *);
struct lassie *
lassie_field_value(
        struct lassie_field *);

unsigned long
lassie_obj_fields_length(
        struct lassie_obj *);

// Array
void
lassie_array_append(
        struct lassie_array *array,
        struct lassie *value);
struct lassie *
lassie_array_drop(
        struct lassie_array *array,
        unsigned long index);

unsigned long
lassie_array_length(
        struct lassie_array *array);

struct lassie *
lassie_array_begin(
        struct lassie_array *);
struct lassie *
lassie_array_next(
        struct lassie_array *,
        struct lassie *);
struct lassie *
lassie_array_index(
        struct lassie_array *,
        unsigned long index);

// Number
long
lassie_number_get_value(
        struct lassie_number *);
void
lassie_number_set_value(
        struct lassie_number *,
        long value);

// String
const char *
lassie_string_get_value(
        struct lassie_string *);
int
lassie_string_set_value(
        struct lassie_string *,
        const char *value);

// Boolean

unsigned int
lassie_boolean_get_value(
        struct lassie_boolean *);
void
lassie_boolean_set_value(
        struct lassie_boolean *,
        unsigned int value);

// Helpers

static inline struct lassie_obj *
lassie_obj_field_obj(
        struct lassie_obj *obj,
        const char *key)
{
    return lassie_to_obj(lassie_obj_get(obj, key));
}
static inline struct lassie_array *
lassie_obj_field_array(
        struct lassie_obj *obj,
        const char *key)
{
    return lassie_to_array(lassie_obj_get(obj, key));
}
static inline struct lassie_number *
lassie_obj_field_number(
        struct lassie_obj *obj,
        const char *key)
{
    return lassie_to_number(lassie_obj_get(obj, key));
}
static inline struct lassie_string *
lassie_obj_field_string(
        struct lassie_obj *obj,
        const char *key)
{
    return lassie_to_string(lassie_obj_get(obj, key));
}
static inline struct lassie_boolean *
lassie_obj_field_boolean(
        struct lassie_obj *obj,
        const char *key)
{
    return lassie_to_boolean(lassie_obj_get(obj, key));
}
static inline struct lassie_null *
lassie_obj_field_null(
        struct lassie_obj *obj,
        const char *key)
{
    return lassie_to_null(lassie_obj_get(obj, key));
}

#endif
