ifndef __KANAWHA_INCLUDE_MK__
define __KANAWHA_INCLUDE_MK__
endef

TPUT ?= $(shell which tput)

ifdef TPUT
COLOR_BLACK=$$($(TPUT) setaf 0)
COLOR_RED=$$($(TPUT) setaf 1)
COLOR_GREEN=$$($(TPUT) setaf 2)
COLOR_YELLOW=$$($(TPUT) setaf 3)
COLOR_LIME_YELLOW=$$($(TPUT) setaf 190)
COLOR_POWDER_BLUE=$$($(TPUT) setaf 153)
COLOR_BLUE=$$($(TPUT) setaf 4)
COLOR_MAGENTA=$$($(TPUT) setaf 5)
COLOR_CYAN=$$($(TPUT) setaf 6)
COLOR_WHITE=$$($(TPUT) setaf 7)
COLOR_BRIGHT=$$($(TPUT) bold)
COLOR_NORMAL=$$($(TPUT) sgr0)
COLOR_BLINK=$$($(TPUT) blink)
COLOR_REVERSE=$$($(TPUT) smso)
COLOR_UNDERLINE=$$($(TPUT) smul)
endif

CC_MSG       := $(COLOR_BRIGHT)$(COLOR_GREEN)CC$(COLOR_NORMAL)
AS_MSG       := $(COLOR_BRIGHT)$(COLOR_RED)AS$(COLOR_NORMAL)
CPP_MSG      := $(COLOR_BRIGHT)$(COLOR_MAGENTA)CPP$(COLOR_NORMAL)
LD_MSG       := $(COLOR_BRIGHT)$(COLOR_YELLOW)LD$(COLOR_NORMAL)
OBJCOPY_MSG  := $(COLOR_BRIGHT)$(COLOR_BLUE)OBJCOPY$(COLOR_NORMAL)
OBJDUMP_MSG  := $(COLOR_BRIGHT)$(COLOR_POWDER_BLUE)OBJCOPY$(COLOR_NORMAL)
CP_MSG       := $(COLOR_BRIGHT)$(COLOR_BLUE)CP$(COLOR_NORMAL)
TOUCH_MSG    := $(COLOR_BRIGHT)$(COLOR_POWDER_BLUE)TOUCH$(COLOR_NORMAL)
FORMAT_MSG   := $(COLOR_BRIGHT)$(COLOR_CYAN)FORMAT$(COLOR_NORMAL)
CPIO_MSG     := $(COLOR_BRIGHT)$(COLOR_LIME_YELLOW)CPIO$(COLOR_NORMAL)


UCC_MSG  := $(COLOR_REVERSE)$(COLOR_BRIGHT)$(COLOR_GREEN)UCC$(COLOR_NORMAL)
UAS_MSG  := $(COLOR_REVERSE)$(COLOR_BRIGHT)$(COLOR_RED)UAS$(COLOR_NORMAL)
UCPP_MSG := $(COLOR_REVERSE)$(COLOR_BRIGHT)$(COLOR_BLUE)UCPP$(COLOR_NORMAL)
ULD_MSG  := $(COLOR_REVERSE)$(COLOR_BRIGHT)$(COLOR_YELLOW)ULD$(COLOR_NORMAL)

ifdef V
	Q ?=
	QPIPE ?=
	QEPIPE ?=
    QIGNORE ?= ||:
else
	Q ?= @
	QPIPE ?= >/dev/null 2>/dev/null
	QEPIPE ?= 2>/dev/null
    QIGNORE ?= ||:
	MAKEFLAGS += -s --no-print-directory
endif

define rel-dir =
$(shell realpath -m --relative-to $2 $1)
endef

define rel-file =
$(shell realpath --relative-to $2 $1)
endef

define abs-dir =
$(shell realpath -m $1)
endef

ifndef V
define qinfo =
	printf "\t$(1)\t\t$2\n"
endef
else
define qinfo =
endef
endif

FORCE:

# Disable builtin rules
.SUFFIXES:

endif
