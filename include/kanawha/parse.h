#ifndef __KANAWHA__PARSE_H__
#define __KANAWHA__PARSE_H__

// Attempts to parse a string as an (unsigned)(int/long/long long)
// (Uses decimal unless prefixed by 0x (hex) or 0 (octal))
// (Signed version can understand +/- prefixes (assumes positive if missing))
// If parsing fails for some reason, returns "def"
int
parse_int(const char *str, int def);
long
parse_long(const char *str, long def);
long long
parse_long_long(const char *str, long long def);
unsigned int
parse_unsigned_int(const char *str, unsigned int def);
unsigned long
parse_unsigned_long(const char *str, unsigned long def);
unsigned long long
parse_unsigned_long_long(const char *str, unsigned long long def);

// Base parsing functions of any base
// Returns 0 on success, errno value on failure
// (Does not expect any prefixes or signs)
int
kstrtoull(const char *str, int base, unsigned long long *out);
int
kstrtoul(const char *str, int base, unsigned long *out);
int
kstrtou(const char *str, int base, unsigned int *out);

#endif
