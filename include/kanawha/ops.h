#ifndef __KERNEL__OPS_H__
#define __KERNEL__OPS_H__

#include <kanawha/printk.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

/*
 * API Overview
 */

// SIG Macros
//
// A SIG Macro defines the signature of a single function.
// They take the form:
//
// #define FILE_OPEN_SIG(RET,ARG)\
// RET(void)
//
// #define FILE_READ_SIG(RET,ARG)\
// RET(int)\
// ARG(void *, dst)\
// ARG(size_t, src_offset)\
// ARG(size_t, size)
//
// #define FILE_WRITE_SIG(RET,ARG)\
// RET(int)\
// ARG(size_t, dst_offset)\
// ARG(void *, src)\
// ARG(size_t, size)

// OP_LIST Macros
//
// An OP_LIST is an X-Macro of the form:
//
// #define FILE_OP_LIST(OP, ...)\
// OP(open, FILE_OPEN_SIG, ##__VA_ARGS__)\
// OP(read, FILE_READ_SIG, ##__VA_ARGS__)\
// OP(write, FILE_WRITE_SIG, ##__VA_ARGS__)
//
// which corresponds to an op list with two functions,
// read and write, which have signatures defined by the SIG
// macros FILE_READ_SIG and FILE_WRITE_SIG.

/*
 * Once the above macros have been declared, then the following set
 * of macros can be used to generate code from them automatically.
 */

/*
 * DECLARE_OP_LIST_PTRS(OP_LIST, THIS_TYPE)
 */
// Declares a set of function pointers from an OP_LIST macro
//
// Ex.
//
// struct file_ops {
// DECLARE_OP_LIST_PTRS(FILE_OP_LIST, struct file *)
// };
//
// will result in
//
// struct file_ops {
//   void(*open)(struct file *);
//   int(*read)(struct file *, void *, size_t, size_t);
//   int(*write)(struct file *, size_t, void *, size_t);
// }
//
// STATE_TYPE is the type of the "this" field which will get passed
// into every function

/*
 * DECLARE_OP_LIST_WRAPPERS(OP_LIST, QUALIFIERS, NAMESPACE, STRUCT_NAME)
 */
// Declares a set of wrapper functions for the OP_LIST on STRUCT_NAME
// Allows for NAMESPACE and QUALIFIERS to be set as well
//
// Ex.
//
// DECLARE_OP_LIST_WRAPPERS(FILE_OP_LIST, static, my_, file)
//
// will result in
//
// static int my_file_open(struct file *);
// static int my_file_read(struct file *, void *, size_t, size_t);
// static int my_file_write(struct file *, size_t, void *, size_t);

/*
 * DEFINE_OP_LIST_WRAPPERS(OP_LIST, QUALIFIERS, NAMESPACE, STRUCT_NAME, OP_FIELD_ACCESSOR, THIS_FIELD_ACCESSOR)
 */
// Defines the functions declared by DECLARE_OP_LIST_WRAPPERS
//
// The two new fields are OP_FIELD_ACCESSOR, which is the accessor used to go from a struct STRUCT_NAME pointer to
// a specific OP_LIST function pointer.
//
// For some common patterns the following ACCESSOR(s) are defined
#define INLINE_OPS_ACCESSOR(__self, __field) __self->__field
#define OPS_STRUCT_PTR_ACCESSOR(__self, __field) __self->ops->__field
#define DRIVER_STRUCT_PTR_ACCESSOR(__self, __field) __self->driver->__field

#define SELF_ACCESSOR
#define STATE_ACCESSOR ->state

// Helper Macros
#define __NOTHING(...) 
#define __RET_IDENTITY(x) x
#define __ARG_COMMA_DECL(type, name) , type name
#define __ARG_DECL_COMMA(type, name) type name ,
#define __ARG_COMMA_TYPE(type, name) , type
#define __ARG_COMMA_NAME(type, name) , name

#define SIG_RETURN_TYPE(SIG) SIG(__RET_IDENTITY,__NOTHING)
#define SIG_ARG_TYPE_LIST(SIG) SIG(__NOTHING,__ARG_COMMA_TYPE)
#define SIG_ARG_DECLS(SIG) SIG(__NOTHING,__ARG_COMMA_DECL)
#define SIG_ARG_NAMES(SIG) SIG(__NOTHING,__ARG_COMMA_NAME)

// Single Function Pointer Declaration
#define DECLARE_OP_PTR(FUNC, SIG, THIS_TYPE, ...)\
    SIG_RETURN_TYPE(SIG) (*FUNC) (THIS_TYPE SIG_ARG_DECLS(SIG));

// Declare Function Pointers from an OP_LIST
#define DECLARE_OP_LIST_PTRS(OP_LIST, THIS_TYPE)\
    OP_LIST(DECLARE_OP_PTR, THIS_TYPE)

// Single Wrapper Function Declaration
#define DECLARE_OP_WRAPPER(FUNC, SIG, STRUCT_NAME, PREFIX, QUALIFIERS)\
    QUALIFIERS SIG_RETURN_TYPE(SIG) PREFIX ## STRUCT_NAME ## _ ## FUNC (struct STRUCT_NAME* SIG_ARG_DECLS(SIG));

// Declare Wrapper Functions for an OP_LIST on struct STRUCT_NAME
#define DECLARE_OP_LIST_WRAPPERS(OP_LIST, QUALIFIERS, NAMESPACE, STRUCT_NAME)\
    OP_LIST(DECLARE_OP_WRAPPER, STRUCT_NAME, NAMESPACE, QUALIFIERS)


// Define a Single OP Wrapper
#define DEFINE_OP_WRAPPER(FUNC, SIG, QUALIFIERS, NAMESPACE, STRUCT_NAME, OP_FIELD_ACCESSOR, THIS_FIELD_ACCESSOR)\
    QUALIFIERS \
    SIG_RETURN_TYPE(SIG) \
    NAMESPACE ## STRUCT_NAME ## _ ## FUNC(struct STRUCT_NAME * __ ## STRUCT_NAME SIG_ARG_DECLS(SIG)) \
    {\
        DEBUG_ASSERT(KERNEL_ADDR(__ ## STRUCT_NAME));\
        if(OP_FIELD_ACCESSOR(__ ## STRUCT_NAME, FUNC)) {\
            DEBUG_ASSERT(KERNEL_ADDR(OP_FIELD_ACCESSOR(__ ## STRUCT_NAME, FUNC)));\
            return (*(OP_FIELD_ACCESSOR(__ ## STRUCT_NAME, FUNC)))(\
                    __ ## STRUCT_NAME THIS_FIELD_ACCESSOR\
                    SIG_ARG_NAMES(SIG));\
        }\
        panic("Calling \""#FUNC"\" on instance of struct \""#STRUCT_NAME"\" with NULL function pointer!");\
    }

//  Define the Wrapper Functions for an OP_LIST
#define DEFINE_OP_LIST_WRAPPERS(OP_LIST, QUALIFIERS, NAMESPACE, STRUCT_NAME, OP_FIELD_ACCESSOR, THIS_FIELD_ACCESSOR)\
    OP_LIST(DEFINE_OP_WRAPPER, QUALIFIERS, NAMESPACE, STRUCT_NAME, OP_FIELD_ACCESSOR, THIS_FIELD_ACCESSOR)

#endif
