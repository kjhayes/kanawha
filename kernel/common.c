#include <kanawha/common.h>

__attribute__((weak))
void arch_pause(void) {
    return; // No-Op
}
