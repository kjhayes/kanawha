#ifndef __KANAWHA__UAPI_SIGNATURE_H__
#define __KANAWHA__UAPI_SIGNATURE_H__

#define __EVAL(__X) __X
#define __MACRO_ARGS(...) (__VA_ARGS__)
#define __MACRO_CALL(__MACRO_FUNC, __ARGS)                                     \
    __EVAL(__MACRO_FUNC __MACRO_ARGS(__ARGS))

#define __NOTHING(...)
#define __SIG_RET_TYPE(__TYPE) __TYPE
#define __SIG_ARG_NAME(__TYPE, __NAME) , __NAME
#define __SIG_ARG_TYPE(__TYPE, __NAME) , __TYPE
#define __SIG_ARG_DECL(__TYPE, __NAME) , __TYPE __NAME

#define __DROP_LEADING_COMMA(__IGN, ...) __VA_ARGS__

#define SIG_RETURN_TYPE(SIG) SIG(__SIG_RET_TYPE, __NOTHING)
#define __SIG_ARG_NAMES(SIG) SIG(__NOTHING, __SIG_ARG_NAME)
#define __SIG_ARG_TYPES(SIG) SIG(__NOTHING, __SIG_ARG_TYPE)
#define __SIG_ARG_DECLS(SIG) SIG(__NOTHING, __SIG_ARG_DECL)

#define SIG_ARG_NAMES(SIG)                                                     \
    __MACRO_CALL(__DROP_LEADING_COMMA, __SIG_ARG_NAMES(SIG))
#define SIG_ARG_TYPES(SIG)                                                     \
    __MACRO_CALL(__DROP_LEADING_COMMA, __SIG_ARG_TYPES(SIG))
#define SIG_ARG_DECLS(SIG)                                                     \
    __MACRO_CALL(__DROP_LEADING_COMMA, __SIG_ARG_DECLS(SIG))

#define SIG_ARG_NAMES_LEADING_COMMA(SIG) __SIG_ARG_NAMES(SIG)
#define SIG_ARG_TYPES_LEADING_COMMA(SIG) __SIG_ARG_TYPES(SIG)
#define SIG_ARG_DECLS_LEADING_COMMA(SIG) __SIG_ARG_DECLS(SIG)

#endif
