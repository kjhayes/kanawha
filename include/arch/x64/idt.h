#ifndef __KANAWHA__IDT_H__
#define __KANAWHA__IDT_H__

#include <arch/x64/segdesc.h>
#include <kanawha/attribute.h>
#include <kanawha/types.h>

extern struct idt64 x64_idt64;

void
x64_init_idt_bsp(void);
void
x64_init_idt_ap(void);

#endif
