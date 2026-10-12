#ifndef __LASSIE_LIST_H__
#define __LASSIE_LIST_H__

#include <stddef.h>
#include <stdio.h>

#ifndef container_of
#define container_of(__ptr, __struct, __member)\
    ({\
     (__struct*)(((void*)(__ptr)) - (offsetof(__struct,__member)));\
     })
#endif

typedef struct list_node {
    struct list_node *next;
    struct list_node *prev;
} list_node_t;

typedef struct list {
    struct list_node *head;
} list_t;

static inline void
list_init(list_t *list)
{
    list->head = NULL;
}

static inline int
list_empty(list_t *list)
{
    return list->head == NULL;
}

static inline unsigned long
list_count(list_t *list)
{
    if(list->head == NULL) {
        return 0;
    }
    unsigned long count = 1;
    list_node_t *iter = list->head->next;
    while(iter != list->head) {
        count++;
        iter = iter->next;
    }
    return count;
}

static inline void
list_push_head(list_t *list,
               list_node_t *entry)
{
    if(list->head == NULL) {
        entry->next = entry;
        entry->prev = entry;
        list->head = entry;
    } else {
        entry->next = list->head;
        entry->prev = list->head->prev;
        entry->next->prev = entry;
        entry->prev->next = entry;
        list->head = entry;
    }
}

static inline list_node_t *
list_pop_head(list_t *list)
{
    if(list_empty(list)) {
        return NULL;
    }
    list_node_t *head = list->head;
    if(head->next == head) {
        list->head = NULL;
    } else {
        head->next->prev = head->prev;
        head->prev->next = head->next;
        list->head = head->next;
    }
    head->next = head;
    head->prev = head;
    return head;
}

static inline void
list_push_tail(list_t *list,
               list_node_t *entry)
{
    if(list->head == NULL) {
        entry->next = entry;
        entry->prev = entry;
        list->head = entry;
    } else {
        entry->next = list->head;
        entry->prev = list->head->prev;
        entry->next->prev = entry;
        entry->prev->next = entry;
    }
}

static inline list_node_t *
list_pop_tail(list_t *list)
{
    if(list_empty(list)) {
        return NULL;
    }
    list_node_t *tail= list->head->prev;
    if(tail == list->head) {
        list->head = NULL;
    } else {
        list->head->prev = tail->prev;
        tail->prev->next = list->head;
    }
    tail->next = tail;
    tail->prev = tail;
    return 0;
}

static inline void
list_remove(list_t *list,
            list_node_t *entry)
{
    if(list->head == NULL) {
        // Invalid call
        // TODO
        return;
    }
    if(list->head == entry) {
        list_pop_head(list);
    } else {
        entry->prev->next = entry->next;
        entry->next->prev = entry->prev;
        entry->prev = entry;
        entry->next = entry;
    }
}

static inline list_node_t *
list_begin(list_t *list)
{
    return list->head;
}
static inline list_node_t *
list_next(list_t *list,
          list_node_t *iter)
{
    if(iter->next == list->head) {
        return NULL;
    } else {
        return iter->next;
    }
}

#define DEFINE_CUSTOM_LIST(\
        PREFIX,\
        LIST_TYPE,\
        LIST_FIELD,\
        ELEM_TYPE,\
        ELEM_FIELD)\
\
static inline void \
PREFIX ## _init(LIST_TYPE *l) {\
    list_init(&l->LIST_FIELD);\
}\
static inline int \
PREFIX ## _empty(LIST_TYPE *l) {\
    return list_empty(&l->LIST_FIELD);\
}\
static inline unsigned long \
PREFIX ## _count(LIST_TYPE *l) {\
    return list_count(&l->LIST_FIELD);\
}\
static inline void \
PREFIX ## _push_head(LIST_TYPE *l,\
                     ELEM_TYPE *e) {\
    list_t *_l = &l->LIST_FIELD;\
    list_node_t *_e = &e->ELEM_FIELD;\
    return list_push_head(_l, _e);\
}\
static inline ELEM_TYPE * \
PREFIX ## _pop_head(LIST_TYPE *l) {\
    list_t *_l = &l->LIST_FIELD;\
    list_node_t *n = list_pop_head(_l);\
    if(n == NULL) {return NULL;}\
    ELEM_TYPE *e = container_of(n, ELEM_TYPE, ELEM_FIELD);\
    return e;\
}\
static inline void \
PREFIX ## _push_tail(LIST_TYPE *l,\
                     ELEM_TYPE *e) {\
    list_t *_l = &l->LIST_FIELD;\
    list_node_t *_e = &e->ELEM_FIELD;\
    return list_push_tail(_l, _e);\
}\
static inline ELEM_TYPE * \
PREFIX ## _pop_tail(LIST_TYPE *l) {\
    list_t *_l = &l->LIST_FIELD;\
    list_node_t *n = list_pop_tail(_l);\
    if(n == NULL) {return NULL;}\
    ELEM_TYPE *e = container_of(n, ELEM_TYPE, ELEM_FIELD);\
    return e;\
}\
static inline void \
PREFIX ## _remove(LIST_TYPE *l, ELEM_TYPE *e) {\
    list_t *_l = &l->LIST_FIELD;\
    list_node_t *_e = &e->ELEM_FIELD;\
    list_remove(_l, _e);\
}\
static inline ELEM_TYPE * \
PREFIX ## _begin(LIST_TYPE *l) {\
    list_t *_l = &l->LIST_FIELD;\
    list_node_t *n = list_begin(_l);\
    if(n == NULL) {return NULL;}\
    ELEM_TYPE *e = container_of(n, ELEM_TYPE, ELEM_FIELD);\
    return e;\
}\
static inline ELEM_TYPE * \
PREFIX ## _next(LIST_TYPE *l, ELEM_TYPE *e) {\
    list_t *_l = &l->LIST_FIELD;\
    list_node_t *_e = &e->ELEM_FIELD;\
    _e = list_next(_l, _e);\
    if(_e == NULL) {return NULL;}\
    return container_of(_e, ELEM_TYPE, ELEM_FIELD);\
}\

#endif
