
#include <lassie/lassie.h>
#include <lassie/json.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

static inline void
lassie_json_skip_whitespace(FILE *file)
{
    char c = fgetc(file);
    while(isspace(c)) {
        c = fgetc(file);
    }
    ungetc(c, file);
}

static struct lassie_number *
lassie_json_read_number(
        FILE *file)
{
    int res;
    // TODO: upgrade this to a long (when elk libc supports scanf %ld)
    int value;
    // This is going to allow octal/hex numbers
    // which is not strictly allowed in json, but
    // we'll be lenient. -KJH
    res = fscanf(file, "%d", &value);
    if(res != 1) {
        fprintf(stderr, "lassie_json_read_number: fscanf failed!\n");
        return NULL;
    }
    return lassie_create_number(value);
}

static struct lassie_boolean *
lassie_json_read_boolean(
        FILE *file)
{
    int res;
    res = fscanf(file, "true");
    if(res == 0) {
        return lassie_create_boolean(1);
    }
    res = fscanf(file, "false");
    if(res == 0) {
        return lassie_create_boolean(0);
    }
    return NULL;
}

static struct lassie_null *
lassie_json_read_null(
        FILE *file)
{
    int res;
    res = fscanf(file, "null");
    if(res == 0) {
        return lassie_create_null();
    }
    return NULL;
}

static struct lassie_string *
lassie_json_read_string(
        FILE *file)
{
    char c = fgetc(file);
    if(c != '"') {
        fprintf(stderr, "lassie_json_read_string: failed to get opening quotation mark! (instead got 0x%x)\n",
                (unsigned int)c);
        ungetc(c, file);
        return NULL;
    }

    unsigned long __strbuflen = 0x100;
    unsigned long __strlen = 0x0;
    char *__strbuf = malloc(__strbuflen);
    if(__strbuf == NULL) {
        fprintf(stderr, "lassie_json_read_string: failed to allocate buffer!\n");\
        return NULL;
    }
    memset(__strbuf, 0, __strbuflen);

#define STRBUF_PUSH(__c)\
    do {\
        while(__strlen >= __strbuflen) {\
            __strbuflen *= 2;\
            char *__new = realloc(__strbuf, __strbuflen);\
            if(__new == NULL) {\
                fprintf(stderr, "lassie_json_read_string: failed to grow string buffer!\n");\
                free(__strbuf);\
                return NULL;\
            }\
        }\
        __strbuf[__strlen] = __c;\
        __strlen++;\
    } while(0)

    unsigned int escaped = 0;
    while(1) {
        char c = fgetc(file);
        if(!escaped && c == '\\') {
            escaped = 1;
            continue;
        }

        if(escaped) {
            switch(c) {
                case '"':
                    STRBUF_PUSH('"');
                    break;
                case '\\':
                    STRBUF_PUSH('\\');
                    break;
                case '/':
                    STRBUF_PUSH('/');
                    break;
                case 'b':
                    STRBUF_PUSH('\b');
                    break;
                case 'f':
                    STRBUF_PUSH('\f');
                    break;
                case 'n':
                    STRBUF_PUSH('\n');
                    break;
                case 'r':
                    STRBUF_PUSH('\r');
                    break;
                case 't':
                    STRBUF_PUSH('\t');
                    break;
                case 'u':
                    {
                        uint16_t value = 0;
                        for(int i = 0; i < 4; i++) {
                            char digit = fgetc(file);
                            uint16_t digit_value = 0;
                            if((digit >= '0' && digit <= '9')) {
                                digit_value = digit - '0';
                            } else if((digit >= 'a' && digit <= 'f')) {
                                digit_value = (digit - 'a') + 10;
                            }
                            else if((digit >= 'A' && digit <= 'F')) {
                                digit_value = (digit - 'a') + 10;
                            }
                            value = (value << 4) | digit_value;
                        }
                        STRBUF_PUSH(((char)value));
                    }
                    break;
                default:
                    STRBUF_PUSH('\\');
                    STRBUF_PUSH(c);
                    break;
            }
            escaped = 0;
            continue;
        } else {
            if(c == '"') {
                break;
            } else {
                STRBUF_PUSH(c);
            }
        }
    }

    STRBUF_PUSH('\0');

    struct lassie_string *str;
    str = lassie_create_string(__strbuf);
    if(str == NULL) {
        fprintf(stderr, "lassie_json_read_string: failed to create string object for string \"%s\"!\n",
                __strbuf);
        free(__strbuf);
        return NULL;
    }
    free(__strbuf);
    return str;

#undef STRBUF_PUSH
}

static struct lassie_obj *
lassie_json_read_obj(
        FILE *file)
{
    int res;

    char c = fgetc(file);
    if(c != '{') {
        ungetc(c, file);
        return NULL;
    }

    struct lassie_obj *obj = lassie_create_obj();
    if(obj == NULL) {
        ungetc(c, file);
        return NULL;
    }

    while(1)
    {
        lassie_json_skip_whitespace(file);

        c = fgetc(file);
        if(c == ',') {
            // Skip empty entries, not-compliant
            // but I like trailing commas -KJH
            continue;
        }
        else if(c == '}') {
            return obj;
        }

        // If this is an opening quotation mark, put it back
        // for lassie_json_read_string to check
        ungetc(c, file);

        struct lassie_string *str;
        str = lassie_json_read_string(file);
        if(str == NULL) {
            fprintf(stderr, "lassie_json_read_obj: failed to read key string!\n");
            lassie_destroy_obj(obj);
            return NULL;
        }

        lassie_json_skip_whitespace(file);

        c = fgetc(file);

        if(c != ':') {
            fprintf(stderr, "lassie_json_read_obj: failed to read key-value separator colon!\n");
            lassie_destroy_string(str);
            lassie_destroy_obj(obj);
            return NULL;
        }

        lassie_json_skip_whitespace(file);

        struct lassie *value;
        value = lassie_json_read(file);
        if(value == NULL) {
            fprintf(stderr, "lassie_json_read_obj: failed to read value!\n");
            lassie_destroy_string(str);
            lassie_destroy_obj(obj);
            return NULL;
        }

        const char *key = lassie_string_get_value(str);

        res = lassie_obj_insert(obj, key, value);
        if(res) {
            fprintf(stderr, "lassie_json_read_obj: failed to insert value into object!\n");
            lassie_destroy_string(str);
            lassie_destroy_obj(obj);
            lassie_destroy(value);
            return NULL;
        }

        lassie_destroy_string(str);
    }
}

static struct lassie_array *
lassie_json_read_array(
        FILE *file)
{
    int res;

    char c = fgetc(file);
    if(c != '[') {
        ungetc(c, file);
        return NULL;
    }

    struct lassie_array *arr = lassie_create_array();
    if(arr == NULL) {
        ungetc(c, file);
        return NULL;
    }

    while(1)
    {
        lassie_json_skip_whitespace(file);

        c = fgetc(file);

        if(c == ',') {
            // We ignore "blank" array entries
            // (not-compliant but I like trailing commas)
            // -KJH
            continue;
        }
        else if(c == ']') {
            return arr;
        }
        else {
            ungetc(c, file);
            struct lassie *value = lassie_json_read(file);
            if(value == NULL) {
                lassie_destroy_array(arr);
                return NULL;
            }
            lassie_array_append(arr, value);
        }
    }
}

struct lassie *lassie_json_read(FILE *file)
{
    lassie_json_skip_whitespace(file);

    char c = fgetc(file);
    ungetc(c, file);

    switch(c) {
        case '{': // Object
            //printf("lassie_json_read: obj\n");
            return lassie_from_obj(lassie_json_read_obj(file));
        case '[': // Array
            //printf("lassie_json_read: array\n");
            return lassie_from_array(lassie_json_read_array(file));
        case '"': // String
            //printf("lassie_json_read: string\n");
            return lassie_from_string(lassie_json_read_string(file));
        case '-':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9': // Number
        {
            //printf("lassie_json_read: number\n");
            struct lassie_number *num = lassie_json_read_number(file);
            //printf("lassie_json_read_number -> %p\n", num);
            return lassie_from_number(num);;
        }
        case 't': // Boolean (true)
        case 'f': // Boolean (false)
            //printf("lassie_json_read: boolean\n");
            return lassie_from_boolean(lassie_json_read_boolean(file));
        case 'n': // Null
            //printf("lassie_json_read: null\n");
            return lassie_from_null(lassie_json_read_null(file));
        default:
            fprintf(stderr, "lassie_json_read: invalid character 0x%x\n", (unsigned int)c);
            return NULL;
    }
    
}

static inline int
putc_repr(FILE *file, char c)
{
    if(isgraph(c)) {
        fputc(c,file);
    }
}
int lassie_json_write(FILE *file, struct lassie *value, unsigned long flags, int depth)
{
    int initial_indent = 1;
#define PRINT_DEPTH(_depth) \
    if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {\
        if(!initial_indent || !(flags & LASSIE_JSON_WRITE_NO_INITIAL_INDENT)) {\
            for(int depth_i = 0; depth_i < _depth; depth_i++) {\
                fprintf(file, " ");\
            }\
        }\
        initial_indent = 0;\
    }

    struct lassie_obj *obj;
    struct lassie_array *array;
    struct lassie_number *number;
    struct lassie_string *string;
    struct lassie_boolean *boolean;
    struct lassie_null *null;

    if((obj = lassie_to_obj(value))) {
        PRINT_DEPTH(depth);
        fprintf(file, "{");
        if(!(flags & LASSIE_JSON_WRITE_COMPACT) && lassie_obj_fields_length(obj) > 1) {
            fprintf(file, "\n");
        }

        int count = 0;
        int first = 1;
        struct lassie_field *field;
        field = lassie_obj_fields_begin(obj);
        while(field) {
            const char *key = lassie_field_key(field);
            struct lassie *value = lassie_field_value(field); 
            if(key == NULL || value == NULL) {
                field = lassie_obj_fields_next(obj, field);
                continue;
            }
            if(!first) {
                fprintf(file, ",");
                if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                    fprintf(file, "\n");
                    PRINT_DEPTH(depth);
                }
            }
            fprintf(file, "\"%s\" : ", key);
            lassie_json_write(file, value, flags | (LASSIE_JSON_WRITE_NO_INITIAL_INDENT), depth+1);
            count++;
            first = 0;
            field = lassie_obj_fields_next(obj, field);
        }
        if(count > 1) {
            if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                fprintf(file, "\n");
            }
            PRINT_DEPTH(depth);
        }
        fprintf(file, "}");
        return 0;
    }
    else if((array = lassie_to_array(value))) {

        PRINT_DEPTH(depth);
        fprintf(file, "[");

        unsigned long i = 0;
        struct lassie *elem = lassie_array_begin(array);
        while(elem) {
            if(i > 0) {
                fprintf(file, ",");
            }
            if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                fprintf(file, "\n");
            }
            PRINT_DEPTH(depth);
            lassie_json_write(file, elem, flags & ~(LASSIE_JSON_WRITE_NO_INITIAL_INDENT), depth+1);
            i++;
            elem = lassie_array_next(array, elem);
        }
        if(lassie_array_length(array) > 0) {
            if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                fprintf(file, "\n");
            }
            PRINT_DEPTH(depth);
        }
        fprintf(file, "]");
        return 0;
    }
    else if((number = lassie_to_number(value))) {
        PRINT_DEPTH(depth);
        fprintf(file, "%ld", lassie_number_get_value(number));
        return 0;
    }
    else if((string = lassie_to_string(value))) {
        PRINT_DEPTH(depth);
        fprintf(file, "\"");
        {
            const char *iter = lassie_string_get_value(string);
            while(iter && *iter) {
                putc_repr(file, *iter);
                iter++;
            }
        }
        fprintf(file, "\"");
        return 0;
    }
    else if((boolean = lassie_to_boolean(value))) {
        PRINT_DEPTH(depth);
        if(lassie_boolean_get_value(boolean)) {
            fprintf(file, "true");
        } else {
            fprintf(file, "false");
        }
        return 0;
    }
    else if((null = lassie_to_null(value))) {
        PRINT_DEPTH(depth);
        fprintf(file, "null");
        return 0;
    }

    fprintf(stderr, "lassie_json_write: invalid lassie term!\n");
    return -EINVAL;

#undef PRINT_DEPTH
}

