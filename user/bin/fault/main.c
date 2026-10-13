
#include <kanawha/sys-wrappers.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static inline uint64_t __attribute__((always_inline))
rdtsc (void)
{
    uint32_t lo, hi;
    __asm__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | ((uint64_t)(hi) << 32);
}

struct {
    uint32_t offset;
    uint16_t selector;
} __attribute__((packed))
call_gate = {
    .offset = 0UL,
    .selector = 0x38UL | 0x0UL,
};

struct stats {
    unsigned long to_kernel;
    unsigned long from_kernel;
    unsigned long total;
};

static inline int
run_test(struct stats *stats)
{
    uint32_t lo, hi;
    uint64_t before = rdtsc();
    __asm__ volatile (
	    "leaq call_gate, %%rax;"
        "rex64 lcall *(%%rax);"
	    : "=a" (lo), "=d" (hi));

    uint64_t after = rdtsc();
    uint64_t in_kernel_time = lo | ((uint64_t)(hi) << 32);

    if(before > in_kernel_time || in_kernel_time > after || before > after) {
        // Discard this test
        printf("Discarding test due to rdtsc overflow!\n");
        return 1;
    }

    uint64_t entry = in_kernel_time - before;
    uint64_t ret = after - in_kernel_time;
    uint64_t total = after-before;

    if(stats) {
        stats->to_kernel = entry;
        stats->from_kernel = ret;
        stats->total = total;
    }

    return 0;
}

int main(int argc, const char **argv)
{
    size_t runs = 0;

    struct stats min = {
        .total = ~0UL,
        .to_kernel = ~0UL,
        .from_kernel = ~0UL,
    };
    struct stats max = {
        .total = 0,
        .to_kernel = 0,
        .from_kernel = 0,
    };
    struct stats sum = {
        .total = 0,
        .to_kernel = 0,
        .from_kernel = 0,
    };

    for(size_t i = 0; i < 100000; i++) {

        struct stats cur = {0};
	    int discard = run_test(&cur);
        if(discard) {
            continue;
        }

        if(cur.total < min.total) {
            min.total = cur.total;
        }
        if(cur.to_kernel < min.to_kernel) {
            min.to_kernel = cur.to_kernel;
        }
        if(cur.from_kernel < min.from_kernel) {
            min.from_kernel = cur.from_kernel;
        }

        if(cur.total > max.total) {
            max.total = cur.total;
        }
        if(cur.to_kernel > max.to_kernel) {
            max.to_kernel = cur.to_kernel;
        }
        if(cur.from_kernel > max.from_kernel) {
            max.from_kernel = cur.from_kernel;
        }

	    sum.total += cur.total;
	    sum.to_kernel += cur.to_kernel;
	    sum.from_kernel += cur.from_kernel;

	    runs++;
    }

    printf("Total Cycles: Minimum(%lu) Maximum(%lu) Avg(%lu)\n",
	    min.total, max.total, sum.total / runs);
    printf("Entry Cycles: Minimum(%lu) Maximum(%lu) Avg(%lu)\n",
	    min.to_kernel, max.to_kernel, sum.to_kernel/ runs);
    printf("Return Cycles: Minimum(%lu) Maximum(%lu) Avg(%lu)\n",
	    min.from_kernel, max.from_kernel, sum.from_kernel/ runs);

    return 0;
}
