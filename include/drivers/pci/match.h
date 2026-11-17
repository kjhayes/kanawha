#ifndef __KANAWHA_DRIVERS_PCI_MATCH_H__
#define __KANAWHA_DRIVERS_PCI_MATCH_H__

#include <kanawha/list.h>
#include <kanawha/lock.h>

DECLARE_GLOBAL_THREAD_LOCK(pci_match_lock);

extern ilist_t pci_driver_list;
extern ilist_t pci_unmatched_func_list;
extern ilist_t pci_matched_func_list;

#endif
