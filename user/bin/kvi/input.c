
#include "input.h"
#include <ilist.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static ilist_t input_source_list;

static void
lock_input_list(void) {}
static void
unlock_input_list(void) {}

int input_init(void) {
    ilist_init(&input_source_list);
    return 0;
}
int input_deinit(void) {
    return 0;
}

struct input_source {
    FILE *file;
    ilist_node_t list_node;
};

int
add_file_input_source(FILE *file)
{
    struct input_source *source;
    source = malloc(sizeof(*source));
    if(source == NULL) {
        return -ENOMEM;
    }
    source->file = file;
    lock_input_list();
    ilist_push_head(&input_source_list, &source->list_node);
    unlock_input_list();
    return 0;
}

char input_source_getc(
        struct input_source *src);

// Get a character from the current input source
char input_getc(void)
{
    ilist_node_t *node;
    node = ilist_peek_head(&input_source_list);
    if(node == NULL) {
        return 0;
    }
    struct input_source *src =
        container_of(node, struct input_source, list_node);
    FILE *file = src->file;
    return fgetc(file);
}


