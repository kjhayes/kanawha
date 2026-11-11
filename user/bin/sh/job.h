#ifndef __KANAWHA__SH_JOB_H__
#define __KANAWHA__SH_JOB_H__

struct job;
struct jobset;

struct jobset *
jobset_create(void);
int
jobset_destroy(
        struct jobset *);

struct jobset *
job_create(void);
int
job_destroy(
        struct job *);
#endif
