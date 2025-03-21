#ifndef __KANAWHA__STACK_H__
#define __KANAWHA__STACK_H__

#include <kanawha/types.h>
#include <kanawha/vmem.h>

struct thread_stack
{
    uintptr_t stack_pointer; // Offset 0 DO NOT MOVE

    uintptr_t stack_base; // highest address
    uintptr_t stack_top; // lowest address

    struct vmem_region *region;
    uintptr_t virt_base;
    order_t virt_order;

    order_t order;
    void __phys * page;
};

int
thread_stack_init(
        struct thread_stack *thread,
        order_t order);

int
thread_stack_deinit(
        struct thread_stack *thread);

#define thread_stack_alloca(_STACK_STATE_PTR, _AMT)\
  ({\
   void *val;\
   (_STACK_STATE_PTR)->stack_pointer -= (uint64_t)(_AMT);\
   val = (void*)((_STACK_STATE_PTR)->stack_pointer);\
   val;\
   })

#define thread_stack_push(_STACK_STATE_PTR, _VALUE)\
  do {\
    (_STACK_STATE_PTR)->stack_pointer -= sizeof(_VALUE);\
    *((typeof(_VALUE)*)(_STACK_STATE_PTR)->stack_pointer) = (_VALUE);\
  } while(0)

#endif
