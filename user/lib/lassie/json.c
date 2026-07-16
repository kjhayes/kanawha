
#include <lassie/lassie.h>
#include <lassie/json.h>
#include <stdio.h>
#include <ctype.h>

struct lassie *lassie_json_read(FILE *file)
{
    unsigned parsing = 1;
    while(parsing) {
        char c = fgetc(file);
        if(isspace(c)) {
            continue;
        }
        switch(c) {
            case '{': // Object
                // TODO
                break;
            case '[': // Array
                // TODO
                break;
            case '"': // String
                // TODO
                break;
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
                // TODO
                break;
            case 't': // Boolean (true)
                // TODO
                break;
            case 'f': // Boolean (false)
                // TODO
                break;
            case 'n': // Null
                // TODO
                break;
        }
    }
    return NULL;
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
#define PRINT_DEPTH(_depth) \
    if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {\
        for(int depth_i = 0; depth_i < _depth; depth_i++) {\
            fprintf(file, "\n");\
        }\
    }

    switch(value->type) {
        case LASSIE_TYPE_NULL:
            PRINT_DEPTH(depth);
            fprintf(file, "null");
            break;
        case LASSIE_TYPE_BOOLEAN:
            PRINT_DEPTH(depth);
            if(value->boolean.value == LASSIE_FALSE) {
                fprintf(file, "false");
            } else {
                fprintf(file, "true");
            }
            break;
        case LASSIE_TYPE_NUMBER:
            PRINT_DEPTH(depth);
            fprintf(file, "%ld", value->number.value);
            break;
        case LASSIE_TYPE_STRING:
            PRINT_DEPTH(depth);
            fprintf(file, "\"");
            {
                char *iter = value->string.value;
                while(iter && *iter) {
                    putc_repr(file, *iter);
                }
            }
            fprintf(file, "\"");
            break;
        case LASSIE_TYPE_OBJ:
            PRINT_DEPTH(depth);
            fprintf(file, "{");
            if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                fprintf(file, "\n");
            }
            int count = 0;
            int first = 1;
            for(int i = 0; i < value->obj.buflen; i++) {
                const char *key = value->obj.buffer[i].key;
                struct lassie *value = value->obj.buffer[i].value;
                if(key == NULL) {
                    continue;
                }
                if(!first) {
                    fprintf(file, ",");
                    if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                        fprintf(file, "\n");
                    }
                }
                PRINT_DEPTH(depth);
                fprintf(file, "\"%s\":", key);
                if(value) {
                    lassie_json_write(file, value, flags, depth+1);
                } else {
                    fprintf(file, "null");
                }
                count++;
                first = 0;
            }
            if(count == 1) {
                if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                    fprintf(file, "\n");
                }
                PRINT_DEPTH(depth);
            }
            fprintf(file, "}");
            break;
        case LASSIE_TYPE_ARRAY:
            PRINT_DEPTH(depth);
            fprintf(file, "[");
            for(int i = 0; i < value->array.buflen; i++) {
                if(i > 0) {
                    fprintf(file, ",");
                }
                if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                    fprintf(file, "\n");
                }
                PRINT_DEPTH(depth);
                struct lassie *elem = value->array.buffer[i];
                if(elem == NULL) {
                    fprintf(file, "null");
                } else {
                    lassie_json_write(file, elem, flags, depth+1);
                }
            }
            if(value->array.buflen > 0) {
                if(!(flags & LASSIE_JSON_WRITE_COMPACT)) {
                    fprintf(file, "\n");
                }
                PRINT_DEPTH(depth);
                fprintf(file, "[");
            }
    }
    return 0;

#undef PRINT_DEPTH
}

