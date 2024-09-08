
#define VOLATILE_CHECKSUM 0x47474747

.extern x64_volatility_thread_fail

#define REGISTER_XLIST(X)\
X(rax)\
X(rbx)\
X(rcx)\
X(rdx)\
X(rdi)\
X(rsi)\
X(rbp)\
X(r8) \
X(r9) \
X(r10)\
X(r11)\
X(r12)\
X(r13)\
X(r14)\
X(r15)

// Register Strings

.rodata

#define DECLARE_REG_STRING(__reg) \
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

x64_volatility_thread_loop:
#define SET_REGISTER(__reg)\
    movq $VOLATILE_CHECKSUM, %__reg; \

    REGISTER_XLIST(SET_REGISTER)
#undef SET_REGISTER

#define CHECK_REGISTER(__reg)\
    cmpq $VOLATILE_CHECKSUM, %__reg; \
    jz __reg ## _pass_check; \
    movq %__reg, %rsi; \
    movq $VOLATILE_CHECKSUM, %rdx; \
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
    
