#ifndef __LASSIE_LASSIE_H__
#define __LASSIE_LASSIE_H__

struct lassie {
    enum {
        LASSIE_TYPE_NULL = 0,
        LASSIE_TYPE_OBJ,
        LASSIE_TYPE_ARRAY,
        LASSIE_TYPE_NUMBER,
        LASSIE_TYPE_STRING,
        LASSIE_TYPE_BOOLEAN,
    } type;
    union {
        struct {
            unsigned long buflen;
            struct {
                char *key;
                struct lassie *value;
            } *buffer;
        } obj;
        struct {
            unsigned long buflen;
            struct lassie **buffer;
        } array;
        struct {
            long value;
        } number;
        struct {
            char *value;
        } string;
        struct {
            #define LASSIE_FALSE (0)
            #define LASSIE_TRUE  (1)
            unsigned int value : 1;
        } boolean;
    };
};

struct lassie * lassie_alloc_obj(void);
struct lassie * lassie_alloc_array(void);
struct lassie * lassie_alloc_number(void);
struct lassie * lassie_alloc_string(void);
struct lassie * lassie_alloc_boolean(void);
int lassie_free(struct lassie *lassie);

int lassie_obj_insert(struct lassie *obj, char *key, struct lassie *value);
int lassie_obj_set(struct lassie *obj, char *key, struct lassie *value);
struct lassie *lassie_obj_get(struct lassie *obj, char *key);
struct lassie *lassie_obj_drop(struct lassie *obj, char *key);
static inline int
lassie_obj_destroy(struct lassie *obj, char *key)
{
    struct lassie *dropped = lassie_obj_drop(obj, key);
    return lassie_free(dropped);
}

int lassie_array_length(struct lassie *arr);
int lassie_array_set_length(struct lassie *arr, int length);
struct lassie *lassie_array_get(struct lassie *arr, int index);
int lassie_array_set(struct lassie *arr, int index, struct lassie *value);
static inline int
lassie_array_append(struct lassie *arr, struct lassie *value)
{
    int res;
    int len = lassie_array_length(arr);
    res = lassie_array_set_length(arr, len+1);
    if(res) {return res;}
    res = lassie_array_set(arr, len, value);
    if(res) {return res;}
    return res;
}

long lassie_number_get(struct lassie *num);
int lassie_number_set(struct lassie *num, long value);

const char *lassie_string_get(struct lassie *string);
int lassie_string_set(struct lassie *string, const char *value);

unsigned int lassie_boolean_get(struct lassie *boolean);
int lassie_boolean_set(struct lassie *boolean, unsigned int value);

#endif
