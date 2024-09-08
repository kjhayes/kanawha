#ifndef __KANAWHA__UAPI_SPAWN_H__
#define __KANAWHA__UAPI_SPAWN_H__

// The child will live in the same address space as it's parent (default)
#define SPAWN_MMAP_SHARED 0
// Create a copy of the parent process' memory mappings
#define SPAWN_MMAP_CLONE (1ULL<<0)

// Cannot have more than one of SPAWN_MMAP_* set at the same time

// Share a file descriptor table with the parent process (default)
#define SPAWN_FILES_SHARED 0
// The child will clone the file descriptors of it's parent
#define SPAWN_FILES_CLONE (1ULL<<1)
// The child will start out with an empty file descriptor table
#define SPAWN_FILES_NONE (1ULL<<2)

// Cannot have more than one of SPAWN_FILES_* set at the same time

// The child will have the same environment variable table as it's parent (default)
#define SPAWN_ENV_SHARED 0
// The child will clone the environment variables of it's parent
#define SPAWN_ENV_CLONE (1ULL<<3)
// The child will start with an empty environment
#define SPAWN_ENV_NONE (1ULL<<4)

// Cannot have more than one of SPAWN_ENV_* set at the same time

#endif
