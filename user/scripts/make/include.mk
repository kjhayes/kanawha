ifndef __ELK_INCLUDE_MK__
define __ELK_INCLUDE_MK__
endef

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
	@printf "\t$1\t\t$2\n"
endef
else
define qinfo =
endef
endif

FORCE:

# Disable builtin rules
.SUFFIXES:

endif
