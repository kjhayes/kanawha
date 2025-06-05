#ifndef __KANAWHA__UAPI_ENVIRON_H__
#define __KANAWHA__UAPI_ENVIRON_H__

// key -> name of variable
// value -> pointer to buffer to strncpy value
// len -> length of the buffer
#define ENV_GET   0

// key -> name of variable
// value -> value string to set variable
// len -> ignored
#define ENV_SET   1

// key -> name of variable
// value -> ignored
// len -> ignored
#define ENV_CLEAR 2

// key -> name of variable
// value -> ignored
// len -> ignored
#define ENV_EXIST 3

// key -> ignored
// value -> pointer to buffer to strncpy "KEY=VALUE" pairs into
// len -> length of the buffer
#define ENV_DUMP 4

// Clears the entire environment of the calling process
// key -> ignored
// value -> ignored
// len -> ignored
#define ENV_WIPE 5

#endif
