#ifndef __KANAWHA__UAPI_PROCESS_H__
#define __KANAWHA__UAPI_PROCESS_H__

typedef int pid_t;

#define REAP_NON_BLOCKING (1ULL<<0)
#define REAP_ANY          (1ULL<<1)

typedef unsigned long id_t;
typedef id_t uid_t;
typedef id_t gid_t;

#define ROOT_UID ((uid_t)0)

// If set, ignore the "proc" argument and
// target the current process
#define RID_SELF (1ULL<<0)
// If set, ignore the "proc" argument and
// target the parent of the current process
// (If the process has no parent, this will act as RID_SELF
//  e.g. parentless processes appear to be their own parent)
#define RID_PARENT (1ULL<<1)
// Read the UID
#define RID_UID  (1ULL<<2)
// Read the GID
#define RID_GID  (1ULL<<3)
// Read the PID
#define RID_PID  (1ULL<<4)

// If RID_UID and RID_GID are both set
// and do not agree, an error will be returned from "rid"
//
// If RID_PID is set at the same time as RID_UID or RID_GID, and error will be returned from "rid"

// If set, ignore the "proc" argument and
// target the current process
#define WID_SELF (1ULL<<0)
// Set the UID
#define WID_UID  (1ULL<<2)
// Set the GID
#define WID_GID  (1ULL<<3)

#endif
