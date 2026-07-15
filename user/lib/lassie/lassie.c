
#include <lassie/lassie.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static inline struct lassie *
lassie_alloc(void)
{
    struct lassie *lassie = malloc(sizeof(struct lassie));
    lassie->type = LASSIE_TYPE_NULL;
    return lassie;
}

struct lassie * lassie_alloc_obj(void)
{
    struct lassie *obj = lassie_alloc();
    if(obj == NULL) {
        return NULL;
    }
    obj->type = LASSIE_TYPE_OBJ;
    obj->obj.buflen = 0;
    obj->obj.buffer = NULL;
    return obj;
}
struct lassie * lassie_alloc_array(void)
{
    struct lassie *array = lassie_alloc();
    if(array== NULL) {
        return NULL;
    }
    array->type = LASSIE_TYPE_ARRAY;
    array->array.len = 0;
    array->array.buflen = 0;
    array->array.buffer = NULL;
    return array;
}
struct lassie * lassie_alloc_number(void)
{
    struct lassie *number = lassie_alloc();
    if(number == NULL) {
        return NULL;
    }
    number->type = LASSIE_TYPE_NUMBER;
    number->number.value = 0;
    return number;
}
struct lassie * lassie_alloc_string(void)
{
    struct lassie *string = lassie_alloc();
    if(string== NULL) {
        return NULL;
    }
    string->type = LASSIE_TYPE_STRING;
    string->string.value = NULL;
    return string;
}
struct lassie * lassie_alloc_boolean(void)
{
    struct lassie *boolean = lassie_alloc();
    if(boolean == NULL) {
        return NULL;
    }
    boolean->type = LASSIE_TYPE_BOOLEAN;
    boolean->boolean.value = LASSIE_FALSE;
    return boolean;
}
int lassie_free(struct lassie *lassie)
{
    switch(lassie->type) {
        case LASSIE_TYPE_NULL:
        case LASSIE_TYPE_NUMBER:
        case LASSIE_TYPE_BOOLEAN:
            break;
        case LASSIE_TYPE_STRING:
            if(lassie->string.value != NULL) {
                free(lassie->string.value);
            }
            break;
        case LASSIE_TYPE_ARRAY:
            for(int i = 0; i < lassie->array.buflen; i++) {
                if(lassie->array.buffer[i]) {
                    lassie_free(lassie->array.buffer[i]);
                }
            }
            if(lassie->array.buflen > 0) {
                free(lassie->array.buffer);
            }
            break;
        case LASSIE_TYPE_OBJ:
            for(int i = 0; i < lassie->obj.buflen; i++) {
                char *key = lassie->obj.buffer[i].key;
                struct lassie *value = lassie->obj.buffer[i].value;
                if(key) {
                    free(key);
                }
                if(value) {
                    lassie_free(value);
                }
            }
            if(lassie->obj.buflen) {
                free(lassie->obj.buffer);
            }
            break;
    }
    free(lassie);
    return 0;
}

int lassie_obj_insert(struct lassie *obj, char *key, struct lassie *value)
{
    if(obj->type != LASSIE_TYPE_OBJ) {
        return -EINVAL;
    }

    int empty_slot = -1;
    // Check that the key is not already used
    // and find any empty slots that we can.
    for(int i = 0; i < obj->obj.buflen; i++) {
        if(obj->obj.buffer[i].key == NULL) {
            empty_slot = i;
            continue;
        }
        if(strcmp(key,obj->obj.buffer[i].key) == 0) {
            return -EEXIST;
        }
    }

    if(empty_slot < 0) {
        // We need to grow the buffer
#define GROW_STEP (4)
        obj->obj.buflen += GROW_STEP;
        void *newbuf = realloc(obj->obj.buffer, obj->obj.buflen * sizeof(obj->obj.buffer[0]));
        if(newbuf == NULL) {
            obj->obj.buflen -= GROW_STEP;
            return -ENOMEM;
        }
        obj->obj.buffer = newbuf;
        for(int i = obj->obj.buflen - GROW_STEP; i < obj->obj.buflen; i++) {
            obj->obj.buffer[i].key = NULL;
            obj->obj.buffer[i].value = NULL;
        }

        empty_slot = obj->obj.buflen - GROW_STEP;

#undef GROW_STEP
    }

    char *key_dup = strdup(key);
    if(key_dup == NULL) {
        return -ENOMEM;
    }
    obj->obj.buffer[empty_slot].key = key_dup;
    obj->obj.buffer[empty_slot].value = value;
    return 0;
}
int lassie_obj_set(struct lassie *obj, char *key, struct lassie *value)
{
    if(obj->type != LASSIE_TYPE_OBJ) {
        return -EINVAL;
    }

    // Look for an existing entry
    for(int i = 0; i < obj->obj.buflen; i++) {
        if(strcmp(obj->obj.buffer[i].key, key) == 0) {
            struct lassie *existing = obj->obj.buffer[i].value;
            obj->obj.buffer[i].value = value;
            if(existing) {
                lassie_free(existing);
            }
            return 0;
        }
    }

    // Found no existing entry, this is not as efficient
    // because we will search for an existing entry again...
    return lassie_obj_insert(obj, key, value);
}
struct lassie *lassie_obj_get(struct lassie *obj, char *key)
{
    if(obj->type != LASSIE_TYPE_OBJ) {
        return NULL;
    }

    for(int i = 0; i < obj->obj.buflen; i++) {
        if(strcmp(obj->obj.buffer[i].key, key) == 0) {
            struct lassie *existing = obj->obj.buffer[i].value;
            return existing;
        }
    }
    return NULL;
}
struct lassie *lassie_obj_drop(struct lassie *obj, char *key)
{
    if(obj->type != LASSIE_TYPE_OBJ) {
        return NULL;
    }

    for(int i = 0; i < obj->obj.buflen; i++) {
        if(strcmp(obj->obj.buffer[i].key, key) == 0) {
            char *existing_key = obj->obj.buffer[i].key;
            struct lassie *existing_value = obj->obj.buffer[i].value;
            free(obj->obj.buffer[i].key);
            obj->obj.buffer[i].key = NULL;
            obj->obj.buffer[i].value = NULL;
            return existing_value;
        }
    }
    return NULL;
}

int lassie_array_length(struct lassie *arr)
{
    if(arr->type != LASSIE_TYPE_ARRAY) {
        return -EINVAL;
    }
    return arr->array.buflen;
}
int lassie_array_set_length(struct lassie *arr, int length)
{
    if(arr->type != LASSIE_TYPE_ARRAY) {
        return -EINVAL;
    }
    if(arr->array.buflen == length) {
        return 0;
    }

    void *new = realloc(arr->array.buffer, sizeof(struct lassie *) * length);
    if(new == NULL) {
        return -ENOMEM;
    }
    arr->array.buffer = new;

    if(arr->array.buflen < length) {
        for(int i = 0; i < length - arr->array.buflen; i++) {
            arr->array.buffer[arr->array.buflen + i] = NULL;
        }
    }
    
    return 0;
}
struct lassie *lassie_array_get(struct lassie *arr, int index)
{
    if(arr->type != LASSIE_TYPE_ARRAY) {
        return NULL;
    }
    if(index >= arr->array.buflen) {
        return NULL;
    }
    return arr->array.buffer[index];
}
int lassie_array_set(struct lassie *arr, int index, struct lassie *value)
{
    if(arr->type != LASSIE_TYPE_ARRAY) {
        return -EINVAL;
    }
    if(index >= arr->array.buflen) {
        return -EINVAL;
    }
    struct lassie *existing = arr->array.buffer[index];
    arr->array.buffer[index] = value;
    if(existing) {
        lassie_free(existing);
    }
    return 0;
}

long lassie_number_get(struct lassie *num)
{
    if(num->type != LASSIE_TYPE_NUMBER) {
        return -EINVAL;
    }
    return num->number.value;
}
int lassie_number_set(struct lassie *num, long value)
{
    if(num->type != LASSIE_TYPE_NUMBER) {
        return -EINVAL;
    }
    num->number.value = value;
    return 0;
}

const char *lassie_string_get(struct lassie *string)
{
    if(string->type != LASSIE_TYPE_STRING) {
        return NULL;
    }
    return string->string.value;
}
int lassie_string_set(struct lassie *string, const char *value)
{
    if(string->type != LASSIE_TYPE_STRING) {
        return -EINVAL;
    }
    char *old = string->string.value;
    string->string.value = strdup(value);
    if(string->string.value == NULL) {
        string->string.value = old;
        return -ENOMEM;
    }
    free(old);
    return 0;
}

unsigned int lassie_boolean_get(struct lassie *boolean)
{
    if(boolean->type != LASSIE_TYPE_BOOLEAN) {
        return -EINVAL;
    }
    return boolean->boolean.value;
}
int lassie_boolean_set(struct lassie *boolean, unsigned int value)
{
    if(boolean->type != LASSIE_TYPE_BOOLEAN) {
        return -EINVAL;
    }
    boolean->boolean.value = value;
    return 0;
}

