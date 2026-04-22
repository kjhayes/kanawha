#ifndef __ELK_LIBC_POSIX__SCHED_H__
#define __ELK_LIBC_POSIX__SCHED_H__

#include <time.h>

struct sched_param
{
    int sched_priority; // process execution scheduling priority
};

#define SCHED_OTHER (0)
#define SCHED_FIFO (1)
#define SCHED_RR (2)

int
sched_get_priority_max(int);
int
sched_get_priority_min(int);
int
sched_getparam(pid_t, struct sched_param *);
int sched_getscheduler(pid_t);
int
sched_rr_get_interval(pid_t, struct timespec *);
int
sched_setparam(pid_t, const struct sched_param *);
int
sched_setscheduler(pid_t, int, const struct sched_param *);
int
sched_yield(void);

// Non-Standard

typedef struct cpu_set cpu_set_t;

void
CPU_ZERO(cpu_set_t *set);

void
CPU_SET(int cpu, cpu_set_t *set);
void
CPU_CLR(int cpu, cpu_set_t *set);
int
CPU_ISSET(int cpu, cpu_set_t *set);

int
CPU_COUNT(cpu_set_t *set);

void
CPU_AND(cpu_set_t *destset, cpu_set_t *srcset1, cpu_set_t *srcset2);
void
CPU_OR(cpu_set_t *destset, cpu_set_t *srcset1, cpu_set_t *srcset2);
void
CPU_XOR(cpu_set_t *destset, cpu_set_t *srcset1, cpu_set_t *srcset2);

int
CPU_EQUAL(cpu_set_t *set1, cpu_set_t *set2);

cpu_set_t *
CPU_ALLOC(int num_cpus);
void
CPU_FREE(cpu_set_t *set);
size_t
CPU_ALLOC_SIZE(int num_cpus);

void
CPU_ZERO_S(size_t setsize, cpu_set_t *set);

void
CPU_SET_S(int cpu, size_t setsize, cpu_set_t *set);
void
CPU_CLR_S(int cpu, size_t setsize, cpu_set_t *set);
int
CPU_ISSET_S(int cpu, size_t setsize, cpu_set_t *set);

int
CPU_COUNT_S(size_t setsize, cpu_set_t *set);

void
CPU_AND_S(size_t setsize,
          cpu_set_t *destset,
          cpu_set_t *srcset1,
          cpu_set_t *srcset2);
void
CPU_OR_S(size_t setsize,
         cpu_set_t *destset,
         cpu_set_t *srcset1,
         cpu_set_t *srcset2);
void
CPU_XOR_S(size_t setsize,
          cpu_set_t *destset,
          cpu_set_t *srcset1,
          cpu_set_t *srcset2);

int
CPU_EQUAL_S(size_t setsize, cpu_set_t *set1, cpu_set_t *set2);

int
sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
int
sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);

#endif
