#ifndef __KANAWHA__ELK_ILIST_H__
#define __KANAWHA__ELK_ILIST_H__

#include <unistd.h>

struct ilist_head
{
    struct ilist_head *next;
    struct ilist_head *prev;
};

typedef struct ilist_head ilist_t;
typedef struct ilist_head ilist_node_t;

#define DECLARE_ILIST(__list)                                                  \
    ilist_t __list = {                                                         \
        .next = &__list,                                                       \
        .prev = &__list,                                                       \
    }

#define ilist_for_each(node, list)                                             \
    for(node = (list)->next; node != (list); node = (node)->next)

static inline void
ilist_init(ilist_t *list)
{
    list->next = list;
    list->prev = list;
}

static inline size_t
ilist_count(ilist_t *list)
{
    size_t len = 0;
    ilist_node_t *node = list->next;
    while(node != list)
    {
        len++;
        node = node->next;
    }
    return len;
}

static inline void
ilist_push_head(ilist_t *list, ilist_node_t *node)
{
    ilist_node_t *cur_head = list->next;

    // Attach previous head and new head
    cur_head->prev = node;
    node->next = cur_head;

    // Attach list to new head
    node->prev = list;
    list->next = node;
}

static inline void
ilist_push_tail(ilist_t *list, ilist_node_t *node)
{
    ilist_node_t *cur_tail = list->prev;

    // Attach previous tail to new tail
    cur_tail->next = node;
    node->prev = cur_tail;

    // Attach new tail to list
    node->next = list;
    list->prev = node;
}

static inline ilist_node_t *
ilist_pop_head(ilist_t *list)
{
    if(list->next == list)
    {
        return NULL;
    }
    ilist_node_t *head = list->next;

    list->next = head->next;
    list->next->prev = list;

    head->next = head;
    head->prev = head;

    return head;
}

static inline ilist_node_t *
ilist_pop_tail(ilist_t *list)
{
    if(list->prev == list)
    {
        return NULL;
    }

    ilist_node_t *tail = list->prev;
    list->prev = tail->prev;
    list->prev->next = list;

    tail->next = tail;
    tail->prev = tail;

    return tail;
}

static inline void
ilist_remove(ilist_t *list, ilist_node_t *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node;
    node->next = node;
}

static inline void
ilist_remove_all(ilist_t *list)
{
    list->next = list;
    list->prev = list;
}

static inline int
ilist_empty(ilist_t *list)
{
    return list->next == list;
}

static inline int
ilist_contains(ilist_t *list, ilist_node_t *node)
{
    ilist_node_t *iter;
    ilist_for_each(iter, list)
    {
        if(node == iter)
        {
            return 1;
        }
    }
    return 0;
}

static inline void
ilist_insert_before(ilist_t *list, ilist_node_t *to_insert, ilist_node_t *ref)
{
    if(ref == to_insert)
    {
        return;
    }

    if(list->next == ref)
    {
        ilist_push_head(list, to_insert);
        return;
    }

    ref->prev->next = to_insert;
    to_insert->prev = ref->prev;

    ref->prev = to_insert;
    to_insert->next = ref;

    return;
}

static inline ilist_node_t *
ilist_peek_head(ilist_t *list)
{
    if(ilist_empty(list))
    {
        return NULL;
    }
    return list->next;
}

#endif
