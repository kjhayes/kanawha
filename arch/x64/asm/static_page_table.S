#ifndef __KANAWHA__X64_STATIC_PAGE_TABLES_S__
#define __KANAWHA__X64_STATIC_PAGE_TABLES_S__

#include "arch/x64/mmu.h"

.macro DECLARE_PT_LEAF_MAPPING base_paddr=0, entries=512, flags=(X64_PT_LEAF_PRESENT|X64_PT_LEAF_WRITE)
.if \entries
.quad (\base_paddr) | \flags
DECLARE_PT_LEAF_MAPPING (\base_paddr + X64_PT_ENTRY_REGION_SIZE), \entries-1
.endif
.endm

.macro DECLARE_PD_LEAF_MAPPING base_paddr=0, entries=512, flags=(X64_PD_LEAF_PRESENT|X64_PD_LEAF_WRITE|X64_PD_LEAF_PAGE_SIZE)
.if \entries
.quad (\base_paddr) | \flags
DECLARE_PD_LEAF_MAPPING (\base_paddr + X64_PD_ENTRY_REGION_SIZE), \entries-1, \flags
.endif
.endm

.macro DECLARE_PDPT_LEAF_MAPPING base_paddr=0, entries=512, flags=(X64_PDPT_LEAF_PRESENT|X64_PDPT_LEAF_WRITE|X64_PDPT_LEAF_PAGE_SIZE)
.if \entries
.quad (\base_paddr) | \flags
DECLARE_PDPT_LEAF_MAPPING (\base_paddr + X64_PDPT_ENTRY_REGION_SIZE), \entries-1, \flags
.endif
.endm

#endif
