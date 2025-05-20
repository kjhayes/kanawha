#ifndef __KANAWHA__UAPI_PROCESS_H__
#define __KANAWHA__UAPI_PROCESS_H__

typedef int pid_t;

#define REAP_NON_BLOCKING (1ULL<<0)
#define REAP_ANY          (1ULL<<1)

typedef unsigned long uid_t;
typedef unsigned long gid_t;

#define ROOT_UID ((uid_t)0)

#endif
