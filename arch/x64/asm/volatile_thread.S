
#define VOLATILE_CHECKSUM 0x47474747

.extern x64_volatility_thread_fail

#define REGISTER_XLIST(X)\
X(rax, 0)\
X(rbx, 1)\
X(rcx, 2)\
X(rdx, 3)\
X(rdi, 4)\
X(rsi, 5)\
X(rbp, 6)\
X(r8,  7)\
X(r9,  8)\
X(r10, 9)\
X(r11, 10)\
X(r12, 11)\
X(r13, 12)\
X(r14, 13)\
X(r15, 14)

// Register Strings

.rodata

#define DECLARE_REG_STRING(__reg, ...) \
__reg ## _str: ;\
.ascii #__reg ;\
.byte 0 ;

.code64
.text

REGISTER_XLIST(DECLARE_REG_STRING)
#undef DECLARE_REG_STRING

.global x64_volatility_thread
.type x64_volatility_thread,@function
x64_volatility_thread:

    // Enable interrupts
    sti

#define SET_REGISTER(__reg, __offset)\
    movq $(VOLATILE_CHECKSUM + __offset), %__reg; \

    REGISTER_XLIST(SET_REGISTER)
#undef SET_REGISTER

x64_volatility_thread_loop:
#define CHECK_REGISTER(__reg, __offset)\
    cmpq $(VOLATILE_CHECKSUM + __offset), %__reg; \
    jz __reg ## _pass_check; \
    movq %__reg, %rsi; \
    movq $(VOLATILE_CHECKSUM + __offset), %rdx; \
    movabsq $__reg ## _str, %rdi; \
    callq x64_volatility_thread_fail; \
    retq; \
    __reg ## _pass_check: \

    REGISTER_XLIST(CHECK_REGISTER)
#undef CHECK_REGISTER

    jmp x64_volatility_thread_loop

__x64_volatility_thread_fail:
    // rdi should be a string with the register name
    // rsi should be the value of the register
    // rdx should be the checksum value
    
