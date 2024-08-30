#ifndef __KANAWHA__COMMON_H__
#define __KANAWHA__COMMON_H__

void arch_halt(void);
void arch_pause(void);

static inline
void halt(void) {
    arch_halt();
}

static inline
void pause(void) {
    arch_pause();
}

#endif
