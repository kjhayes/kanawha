#ifndef __KANAWHA__IDT_H__
#define __KANAWHA__IDT_H__

struct x64_cpu;
struct x64_idt;

void
x64_init_default_idt_bsp(void);
void
x64_init_default_idt_ap(void);

struct x64_idt *
x64_get_default_idt(void);

int
x64_cpu_set_idt(
        struct x64_idt *idt,
        struct x64_cpu *cpu);

#endif
