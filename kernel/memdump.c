
#include <kanawha/init.h>
#include <kanawha/page_alloc.h>

static int
dump_page_alloc_amounts(void)
{
    size_t amt_free = page_alloc_amount_free();
    size_t amt_cached = page_alloc_amount_cached();

    printk("Free Memory:   %ld MiB %ld KiB %ld Bytes\n",
            amt_free >> 20,
            (amt_free & (1ULL<<20)-1) >> 12,
            (amt_free & (1ULL<<12)-1));
    printk("Cached Memory: %ld MiB %ld KiB %ld Bytes\n",
            amt_cached >> 20,
            (amt_cached & (1ULL<<20)-1) >> 12,
            (amt_cached & (1ULL<<12)-1));

    return 0;
}
declare_init(late, dump_page_alloc_amounts);

