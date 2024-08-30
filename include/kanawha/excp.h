#ifndef __KANAWHA__EXCP_H__
#define __KANAWHA__EXCP_H__

#include <kanawha/printk.h>

// This should never be given a body,
// just used for type-checking 
// (think of struct excp_state * as an
//  architecture defined "void*")
struct excp_state;

void arch_excp_dump_state(struct excp_state *state, printk_f *printer);

#endif
