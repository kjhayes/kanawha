
#include <kanawha/stack.h>
#include <kanawha/vmem.h>
#include <kanawha/thread.h>
#include <kanawha/mem_flags.h>
#include <kanawha/string.h>
#include <kanawha/page_alloc.h>
#include <kanawha/assert.h>
#include <kanawha/proc/process.h>

#define THREAD_STACK_VIRT_SIZE_ORDER 21
#define THREAD_STACK_VIRT_ALIGN_ORDER 21

static int
thread_stack_page_fault_handler(
        struct excp_state *state,
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long flags,
        void *priv_state)
{
    struct thread_stack *stack = priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(stack));

    if(current_thread()) {
        eprintk("Thread(%ld) likely stack overflow!\n",
            current_thread()->id);
    } else {
        eprintk("Page fault on stack [%p - %p) region [%p - %p) page=%p without a current thread!\n",
                stack->stack_top,
                stack->stack_base,
                stack->virt_base,
                stack->virt_base + (1ULL<<stack->virt_order),
                stack->page
                );
    }

    return PAGE_FAULT_UNHANDLED;
}

int
thread_stack_init(
        struct thread_stack *stack,
        order_t order)
{
    int res;

    if(order >= THREAD_STACK_VIRT_SIZE_ORDER) {
        res = -EINVAL;
        goto err0;
    }
    if(order < VMEM_MIN_PAGE_ORDER) {
        res = -EINVAL;
        goto err0;
    }

    stack->order = order;
    res = page_alloc(order, &stack->page, 0);
    if(res) {
        eprintk("Failed to allocate thread stack!\n");
        goto err0;
    }

    stack->region = vmem_region_create_paged(
            1ULL<<THREAD_STACK_VIRT_SIZE_ORDER,
            thread_stack_page_fault_handler,
            (void*)stack);

    if(stack->region == NULL) {
        res = -ENOMEM;
        eprintk("Failed to create thread stack vmem region!\n");
        goto err1;
    }

    uintptr_t virt_base;
    res = mem_flags_find_and_reserve(
            get_virt_mem_flags(),
            1ULL<<THREAD_STACK_VIRT_SIZE_ORDER,
            vmem_region_alignment(stack->region),
            VIRT_MEM_FLAGS_HIGHMEM|VIRT_MEM_FLAGS_AVAIL,
            VIRT_MEM_FLAGS_NONCANON,
            0,
            VIRT_MEM_FLAGS_AVAIL,
            &virt_base);

    if(res) {
        eprintk("Failed to reserve thread stack virtual memory!\n");
        goto err2;
    }

    stack->virt_base = virt_base;
    stack->virt_order = THREAD_STACK_VIRT_SIZE_ORDER;

    // Halfway into the virtual region, giving a large amount
    // of buffer room to catch stack overflows
    stack->stack_top = stack->virt_base + (1ULL<<(stack->virt_order-1));
    stack->stack_base = stack->stack_top + (1ULL<<stack->order);
    stack->stack_pointer = stack->stack_base;
    dprintk("thread_stack = [%p-%p)\n",
            stack->stack_top,
            stack->stack_base);
    res = vmem_paged_region_map(
            stack->region,
            stack->stack_top - stack->virt_base,
            stack->page,
            1ULL<<stack->order,
            VMEM_REGION_READ|VMEM_REGION_WRITE);
    if(res) {
        eprintk("Failed to map thread stack! (err=%s)\n",
                errnostr(res));
        goto err3;
    }

    res = vmem_force_mapping(
            stack->region,
            (void*)stack->virt_base);
    if(res) {
        eprintk("Failed to force mapping of thread stack! (err=%s)\n",
                errnostr(res));
        goto err3;
    }

    memset((void*)stack->stack_top, 0, 1ULL<<stack->order);

    return 0;

//err4:
//    vmem_relax_mapping((void*)stack->virt_base);
err3:
    mem_flags_set_flags(
        get_virt_mem_flags(),
        stack->virt_base,
        1ULL<<stack->virt_order,
        VIRT_MEM_FLAGS_AVAIL);
err2:
    vmem_region_destroy(stack->region);
err1:
    page_free(stack->order, stack->page);
err0:
    return res;
}

int
thread_stack_deinit(
        struct thread_stack *stack)
{
    int res;

    res = vmem_relax_mapping((void*)stack->virt_base);
    if(res) {
        return res;
    }
    res = mem_flags_set_flags(
        get_virt_mem_flags(),
        stack->virt_base,
        1ULL<<stack->virt_order,
        VIRT_MEM_FLAGS_AVAIL);
    if(res) {
        return res;
    }
    res = vmem_region_destroy(stack->region);
    if(res) {
        return res;
    }
    res = page_free(stack->order, stack->page);
    if(res) {
        return res;
    }

    return 0;
}

