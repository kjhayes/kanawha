#ifndef __KANAWHA__ACPI_INTERP_OPCODE_H__
#define __KANAWHA__ACPI_INTERP_OPCODE_H__

#include <kanawha/types.h>
#include <acpi/interp/state.h>

#define ACPI_AML_EXT_OP_PREFIX (0x5B)
#define ACPI_AML_NOT_OP_PREFIX (0x92)
#define AML_NULL_NAME AML_ZERO_OP

#define ACPI_AML_OPCODE_XLIST(X,...)\
X(ZERO_OP,               0x0000, ##__VA_ARGS__)\
X(ONE_OP,                0x0001, ##__VA_ARGS__)\
X(ALIAS_OP,              0x0006, ##__VA_ARGS__)\
X(NAME_OP,               0x0008, ##__VA_ARGS__)\
X(BYTE_PREFIX,           0x000A, ##__VA_ARGS__)\
X(WORD_PREFIX,           0x000B, ##__VA_ARGS__)\
X(DWORD_PREFIX,          0x000C, ##__VA_ARGS__)\
X(STRING_PREFIX,         0x000D, ##__VA_ARGS__)\
X(QWORD_PREFIX,          0x000E, ##__VA_ARGS__)\
X(SCOPE_OP,              0x0010, ##__VA_ARGS__)\
X(BUFFER_OP,             0x0011, ##__VA_ARGS__)\
X(PACKAGE_OP,            0x0012, ##__VA_ARGS__)\
X(VAR_PACKAGE_OP,        0x0013, ##__VA_ARGS__)\
X(METHOD_OP,             0x0014, ##__VA_ARGS__)\
X(EXTERNAL_OP,           0x0015, ##__VA_ARGS__)\
X(DUAL_NAME_PREFIX,      0x002E, ##__VA_ARGS__)\
X(MULTI_NAME_PREFIX,     0x002F, ##__VA_ARGS__)\
X(DIGIT_CHAR_0,          0x0030, ##__VA_ARGS__)\
X(DIGIT_CHAR_1,          0x0031, ##__VA_ARGS__)\
X(DIGIT_CHAR_2,          0x0032, ##__VA_ARGS__)\
X(DIGIT_CHAR_3,          0x0033, ##__VA_ARGS__)\
X(DIGIT_CHAR_4,          0x0034, ##__VA_ARGS__)\
X(DIGIT_CHAR_5,          0x0035, ##__VA_ARGS__)\
X(DIGIT_CHAR_6,          0x0036, ##__VA_ARGS__)\
X(DIGIT_CHAR_7,          0x0037, ##__VA_ARGS__)\
X(DIGIT_CHAR_8,          0x0038, ##__VA_ARGS__)\
X(DIGIT_CHAR_9,          0x0039, ##__VA_ARGS__)\
X(NAME_CHAR_A,           0x0041, ##__VA_ARGS__)\
X(NAME_CHAR_B,           0x0042, ##__VA_ARGS__)\
X(NAME_CHAR_C,           0x0043, ##__VA_ARGS__)\
X(NAME_CHAR_D,           0x0044, ##__VA_ARGS__)\
X(NAME_CHAR_E,           0x0045, ##__VA_ARGS__)\
X(NAME_CHAR_F,           0x0046, ##__VA_ARGS__)\
X(NAME_CHAR_G,           0x0047, ##__VA_ARGS__)\
X(NAME_CHAR_H,           0x0048, ##__VA_ARGS__)\
X(NAME_CHAR_I,           0x0049, ##__VA_ARGS__)\
X(NAME_CHAR_J,           0x004A, ##__VA_ARGS__)\
X(NAME_CHAR_K,           0x004B, ##__VA_ARGS__)\
X(NAME_CHAR_L,           0x004C, ##__VA_ARGS__)\
X(NAME_CHAR_M,           0x004D, ##__VA_ARGS__)\
X(NAME_CHAR_N,           0x004E, ##__VA_ARGS__)\
X(NAME_CHAR_O,           0x004F, ##__VA_ARGS__)\
X(NAME_CHAR_P,           0x0050, ##__VA_ARGS__)\
X(NAME_CHAR_Q,           0x0051, ##__VA_ARGS__)\
X(NAME_CHAR_R,           0x0052, ##__VA_ARGS__)\
X(NAME_CHAR_S,           0x0053, ##__VA_ARGS__)\
X(NAME_CHAR_T,           0x0054, ##__VA_ARGS__)\
X(NAME_CHAR_U,           0x0055, ##__VA_ARGS__)\
X(NAME_CHAR_V,           0x0056, ##__VA_ARGS__)\
X(NAME_CHAR_W,           0x0057, ##__VA_ARGS__)\
X(NAME_CHAR_X,           0x0058, ##__VA_ARGS__)\
X(NAME_CHAR_Y,           0x0059, ##__VA_ARGS__)\
X(NAME_CHAR_Z,           0x005A, ##__VA_ARGS__)\
X(ROOT_CHAR,             0x005C, ##__VA_ARGS__)\
X(PARENT_PREFIX_OP,      0x005E, ##__VA_ARGS__)\
X(NAME_CHAR,             0x005F, ##__VA_ARGS__)\
X(LOCAL_0_OP,            0x0060, ##__VA_ARGS__)\
X(LOCAL_1_OP,            0x0061, ##__VA_ARGS__)\
X(LOCAL_2_OP,            0x0062, ##__VA_ARGS__)\
X(LOCAL_3_OP,            0x0063, ##__VA_ARGS__)\
X(LOCAL_4_OP,            0x0064, ##__VA_ARGS__)\
X(LOCAL_5_OP,            0x0065, ##__VA_ARGS__)\
X(LOCAL_6_OP,            0x0066, ##__VA_ARGS__)\
X(LOCAL_7_OP,            0x0067, ##__VA_ARGS__)\
X(ARG_0_OP,              0x0068, ##__VA_ARGS__)\
X(ARG_1_OP,              0x0069, ##__VA_ARGS__)\
X(ARG_2_OP,              0x006A, ##__VA_ARGS__)\
X(ARG_3_OP,              0x006B, ##__VA_ARGS__)\
X(ARG_4_OP,              0x006C, ##__VA_ARGS__)\
X(ARG_5_OP,              0x006D, ##__VA_ARGS__)\
X(ARG_6_OP,              0x006E, ##__VA_ARGS__)\
X(STORE_OP,              0x0070, ##__VA_ARGS__)\
X(REF_OF_OP,             0x0071, ##__VA_ARGS__)\
X(ADD_OP,                0x0072, ##__VA_ARGS__)\
X(CONCAT_OP,             0x0073, ##__VA_ARGS__)\
X(SUBTRACT_OP,           0x0074, ##__VA_ARGS__)\
X(INCREMENT_OP,          0x0075, ##__VA_ARGS__)\
X(DECREMENT_OP,          0x0076, ##__VA_ARGS__)\
X(MULTIPLY_OP,           0x0077, ##__VA_ARGS__)\
X(DIVIDE_OP,             0x0078, ##__VA_ARGS__)\
X(SHIFT_LEFT_OP,         0x0079, ##__VA_ARGS__)\
X(SHIFT_RIGHT_OP,        0x007A, ##__VA_ARGS__)\
X(AND_OP,                0x007B, ##__VA_ARGS__)\
X(NAND_OP,               0x007C, ##__VA_ARGS__)\
X(OR_OP,                 0x007D, ##__VA_ARGS__)\
X(NOR_OP,                0x007E, ##__VA_ARGS__)\
X(XOR_OP,                0x007F, ##__VA_ARGS__)\
X(NOT_OP,                0x0080, ##__VA_ARGS__)\
X(FIND_SET_LEFT_BIT_OP,  0x0081, ##__VA_ARGS__)\
X(FIND_SET_RIGHT_BIT_OP, 0x0082, ##__VA_ARGS__)\
X(DEREF_OF_OP,           0x0083, ##__VA_ARGS__)\
X(CONCAT_RES_OP,         0x0084, ##__VA_ARGS__)\
X(MOD_OP,                0x0085, ##__VA_ARGS__)\
X(NOTIFY_OP,             0x0086, ##__VA_ARGS__)\
X(SIZE_OF_OP,            0x0087, ##__VA_ARGS__)\
X(INDEX_OP,              0x0088, ##__VA_ARGS__)\
X(MATCH_OP,              0x0089, ##__VA_ARGS__)\
X(CREATE_DWORD_FIELD_OP, 0x008A, ##__VA_ARGS__)\
X(CREATE_WORD_FIELD_OP,  0x008B, ##__VA_ARGS__)\
X(CREATE_BYTE_FIELD_OP,  0x008C, ##__VA_ARGS__)\
X(CREATE_BIT_FIELD_OP,   0x008D, ##__VA_ARGS__)\
X(OBJECT_TYPE_OP,        0x008E, ##__VA_ARGS__)\
X(CREATE_QWORD_FIELD_OP, 0x008F, ##__VA_ARGS__)\
X(LAND_OP,               0x0090, ##__VA_ARGS__)\
X(LOR_OP,                0x0091, ##__VA_ARGS__)\
X(LNOT_OP,               0x0092, ##__VA_ARGS__)\
X(LNOT_EQUAL_OP,         0x9293, ##__VA_ARGS__)\
X(LLESS_EQUAL_OP,        0x9294, ##__VA_ARGS__)\
X(LGREATER_EQUAL_OP,     0x9295, ##__VA_ARGS__)\
X(LEQUAL_OP,             0x0093, ##__VA_ARGS__)\
X(LGREATER_OP,           0x0094, ##__VA_ARGS__)\
X(LLESS_OP,              0x0095, ##__VA_ARGS__)\
X(TO_BUFFER_OP,          0x0096, ##__VA_ARGS__)\
X(TO_DECIMAL_STRING_OP,  0x0097, ##__VA_ARGS__)\
X(TO_HEX_STRING_OP,      0x0098, ##__VA_ARGS__)\
X(TO_INTEGER_OP,         0x0099, ##__VA_ARGS__)\
X(TO_STRING_OP,          0x009C, ##__VA_ARGS__)\
X(COPY_OBJECT_OP,        0x009D, ##__VA_ARGS__)\
X(MID_OP,                0x009E, ##__VA_ARGS__)\
X(CONTINUE_OP,           0x009F, ##__VA_ARGS__)\
X(IF_OP,                 0x00A0, ##__VA_ARGS__)\
X(ELSE_OP,               0x00A1, ##__VA_ARGS__)\
X(WHILE_OP,              0x00A2, ##__VA_ARGS__)\
X(NOOP_OP,               0x00A3, ##__VA_ARGS__)\
X(RETURN_OP,             0x00A4, ##__VA_ARGS__)\
X(BREAK_OP,              0x00A5, ##__VA_ARGS__)\
X(BREAK_POINT_OP,        0x00CC, ##__VA_ARGS__)\
X(ONES_OP,               0x00FF, ##__VA_ARGS__)\
X(MUTEX_OP,              0x5B01,  ##__VA_ARGS__)\
X(EVENT_OP,              0x5B02,  ##__VA_ARGS__)\
X(COND_REF_OF_OP,        0x5B12,  ##__VA_ARGS__)\
X(CREATE_FIELD_OP,       0x5B13,  ##__VA_ARGS__)\
X(LOAD_TABLE_OP,         0x5B1F,  ##__VA_ARGS__)\
X(LOAD_OP,               0x5B20,  ##__VA_ARGS__)\
X(STALL_OP,              0x5B21,  ##__VA_ARGS__)\
X(SLEEP_OP,              0x5B22,  ##__VA_ARGS__)\
X(ACQUIRE_OP,            0x5B23,  ##__VA_ARGS__)\
X(SIGNAL_OP,             0x5B24,  ##__VA_ARGS__)\
X(WAIT_OP,               0x5B25,  ##__VA_ARGS__)\
X(RESET_OP,              0x5B26,  ##__VA_ARGS__)\
X(RELEASE_OP,            0x5B27,  ##__VA_ARGS__)\
X(FROM_BCD_OP,           0x5B28,  ##__VA_ARGS__)\
X(TO_BCD_OP,             0x5B29,  ##__VA_ARGS__)\
X(REVISION_OP,           0x5B30,  ##__VA_ARGS__)\
X(DEBUG_OP,              0x5B31,  ##__VA_ARGS__)\
X(FATAL_OP,              0x5B32,  ##__VA_ARGS__)\
X(TIMER_OP,              0x5B33,  ##__VA_ARGS__)\
X(OP_REGION_OP,          0x5B80,  ##__VA_ARGS__)\
X(OP_REGION_FIELDS_OP,   0x5B81,  ##__VA_ARGS__)\
X(DEVICE_OP,             0x5B82,  ##__VA_ARGS__)\
X(PROCESSOR_OP,          0x5B83,  ##__VA_ARGS__)\
X(POWER_RES_OP,          0x5B84,  ##__VA_ARGS__)\
X(THERMAL_ZONE_OP,       0x5B85,  ##__VA_ARGS__)\
X(INDEX_FIELD_OP,        0x5B86,  ##__VA_ARGS__)\
X(BANK_FIELD_OP,         0x5B87,  ##__VA_ARGS__)\
X(DATA_REGION_OP,        0x5B88,  ##__VA_ARGS__)

#define DECLARE_AML_OPCODE_ENUM(__NAME, __VAL)\
    AML_ ## __NAME = __VAL,
typedef enum aml_opcode {
ACPI_AML_OPCODE_XLIST(DECLARE_AML_OPCODE_ENUM)
} aml_opcode_t;

#undef DECLARE_AML_OPCODE_CONSTANTS

const char *
aml_opcode_to_string(aml_opcode_t opcode);

// The opcode written to "out"
// is not necessarily valid,
// even if no errno is returned
ssize_t
aml_parse_opcode(
	void *data,
	size_t datalen,
        aml_opcode_t *out);

int
acpi_interp_peek_aml_opcode(
	struct acpi_interp_state *state,
	aml_opcode_t *out);
int
acpi_interp_aml_opcode(
	struct acpi_interp_state *state,
	aml_opcode_t *out);

#endif
