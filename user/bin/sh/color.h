#ifndef __SH__COLOR_H__
#define __SH__COLOR_H__

#define ANSI_COLOR_CODES

#ifdef ANSI_COLOR_CODES
#ifndef COLOR_BLACK
#define COLOR_BLACK "\e[0;30m"
#endif
#ifndef COLOR_RED
#define COLOR_RED "\e[0;31m"
#endif
#ifndef COLOR_GREEN
#define COLOR_GREEN "\e[0;32m"
#endif
#ifndef COLOR_YELLOW
#define COLOR_YELLOW "\e[0;33m"
#endif
#ifndef COLOR_BLUE
#define COLOR_BLUE "\e[0;34m"
#endif
#ifndef COLOR_MAGENTA
#define COLOR_MAGENTA "\e[0;35m"
#endif
#ifndef COLOR_CYAN
#define COLOR_CYAN "\e[0;36m"
#endif
#ifndef COLOR_WHITE
#define COLOR_WHITE "\e[0;37m"
#endif
#ifndef COLOR_RESET
#define COLOR_RESET "\e[0m"
#endif
#endif

#ifndef COLOR_BLACK
#define COLOR_BLACK ""
#endif
#ifndef COLOR_RED
#define COLOR_RED ""
#endif
#ifndef COLOR_GREEN
#define COLOR_GREEN ""
#endif
#ifndef COLOR_YELLOW
#define COLOR_YELLOW ""
#endif
#ifndef COLOR_BLUE
#define COLOR_BLUE ""
#endif
#ifndef COLOR_MAGENTA
#define COLOR_MAGENTA ""
#endif
#ifndef COLOR_CYAN
#define COLOR_CYAN ""
#endif
#ifndef COLOR_WHITE
#define COLOR_WHITE ""
#endif
#ifndef COLOR_RESET
#define COLOR_RESET ""
#endif

#endif
