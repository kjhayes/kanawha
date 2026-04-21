#ifndef __KANAWHA__LIST_H__
#define __KANAWHA__LIST_H__

#include <kanawha/assert.h>
#include <kanawha/printk.h>
#include <kanawha/types.h>

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

// Check that a list has not become corrupted (it must have valid kernel addr
// for every node
#ifdef CONFIG_DEBUG_ASSERTIONS
#define DEBUG_KERNEL_ILIST_CHECK(list_ptr)                                     \
    do                                                                         \
    {                                                                          \
        size_t elements = 0;\
        ilist_node_t *node;                                                    \
        ilist_for_each(node, (list_ptr))                                       \
        {                                                                      \
            elements++;\
            DEBUG_ASSERT(elements < (1UL<<48)); \
            DEBUG_ASSERT(KERNEL_ADDR(node));                                   \
            DEBUG_ASSERT(KERNEL_ADDR(node->prev));                             \
            DEBUG_ASSERT(KERNEL_ADDR(node->next));                             \
        }                                                                      \
    } while(0)
#else
#define DEBUG_KERNEL_ILIST_CHECK(list_ptr)
#endif

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

    dprintk("ilist_push_tail: list=%p, node=%p\n", list, node);

    // Attach previous tail to new tail
    cur_tail->next = node;
    node->prev = cur_tail;

    // Attach new tail to list
    node->next = list;
    list->prev = node;

    DEBUG_KERNEL_ILIST_CHECK(list);
}

static inline ilist_node_t *
ilist_pop_head(ilist_t *list)
{
    DEBUG_ASSERT(KERNEL_ADDR(list));

    if(list->next == list)
    {
        return NULL;
    }

    DEBUG_ASSERT_MSG(KERNEL_ADDR(list->next),
                     "list = %p, list->next = %p",
                     list,
                     list->next);
    ilist_node_t *head = list->next;
    DEBUG_ASSERT_MSG(KERNEL_ADDR(head->next),
                     "list = %p, head = %p, head->next = %p",
                     list,
                     head,
                     head->next);
    list->next = head->next;
    list->next->prev = list;

    head->next = head;
    head->prev = head;

    DEBUG_KERNEL_ILIST_CHECK(list);
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
    dprintk("ilist_remove list=%p, node=%p\n", list, node);
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
    DEBUG_KERNEL_ILIST_CHECK(list);
    dprintk("ilist_insert_before list=%p, to_insert=%p, ref=%p\n",
            list,
            to_insert,
            ref);

    DEBUG_ASSERT(KERNEL_ADDR(list));
    DEBUG_ASSERT(KERNEL_ADDR(to_insert));
    DEBUG_ASSERT(KERNEL_ADDR(ref));

    if(ref == to_insert)
    {
        eprintk("Tried to insert list node before itself!\n");
        return;
    }

    if(list->next == ref)
    {
        ilist_push_head(list, to_insert);
        return;
    }

    DEBUG_ASSERT(KERNEL_ADDR(ref->prev));
    DEBUG_ASSERT(KERNEL_ADDR(ref->prev->next));
    ref->prev->next = to_insert;
    to_insert->prev = ref->prev;

    ref->prev = to_insert;
    to_insert->next = ref;

    dprintk("ref->prev = %p\n", ref->prev);
    dprintk("ref->next = %p\n", ref->next);
    dprintk("to_insert->prev = %p\n", to_insert->prev);
    dprintk("to_insert->next = %p\n", to_insert->next);

    DEBUG_KERNEL_ILIST_CHECK(list);
    return;
}

static inline ilist_node_t *
ilist_peek_head(ilist_t *list)
{
    if(ilist_empty(list)) {
        return NULL;
    }
    return list->next;
}

#endif
