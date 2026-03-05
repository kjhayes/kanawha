#ifndef __KANAWHA__UAPI_EXEC_H__
#define __KANAWHA__UAPI_EXEC_H__

/*
 * Allow trying to execute files which kernel drivers mark
 * as "maybe" valid during probing, if such a file is actually
 * invalid, then attempting to execute it will result in the
 * process' address space being wiped, and the process almost
 * certainly being killed.
 */
#define EXEC_PERMISSIVE (1ULL << 0)

#endif
